"""
Largely inspired from
https://github.com/gramineproject/gramine/commit/1a1869468aef7085d6c9d722adf9d1d0484e1b4c # noqa: E501
"""

import ctypes
import os
import ssl
import asyncio
from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from asyncio import CancelledError
import socket

NON_STANDARD_INTEL_SGX_QUOTE_OID = "0.6.9.42.840.113741.1337.6"
TCG_DICE_TAGGED_EVIDENCE_OID = "2.23.133.5.4.9"

class AttestationError(Exception):
    pass

class RaTlsCertInfo:
    def __init__(self, crt_bytes_der):
        self.certificate = x509.load_der_x509_certificate(bytes(crt_bytes_der), default_backend())
        extension = self.certificate.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(NON_STANDARD_INTEL_SGX_QUOTE_OID)) # TODO: use evidence format instead
        if (extension is None):
            self.is_ratls = False
            return
        self.is_ratls = True
        self.quote = extension.value.public_bytes()
        self.attributes_flags = int.from_bytes(self.quote[96:104], byteorder="little")
        self.debug_bit = self.quote[96] & 2 > 0
        self.attributes_xfrm = int.from_bytes(self.quote[104:112], byteorder="little")
        self.mr_enclave = self.quote[112:144]
        self.mr_signer = self.quote[176:208]
        self.isv_prodid = int.from_bytes(self.quote[304:306], byteorder="little")
        self.isv_svn = int.from_bytes(self.quote[306:308], byteorder="little")
        self.report_data = self.quote[368:432]

class RaTlsVerifier:
    """
    A TLS cert for RA-TLS that can verify the
    provided RA-TLS certificate.
    """
    def __init__(
        self,
        mr_enclave="any",
        mr_signer="any",
        isv_prod_id=0,
        isv_svn=0,
        allow_debug_enclave_insecure=True,
        allow_outdated_tcb_insecure=True,
        allow_hw_config_needed=True,
        allow_sw_hardening_needed=True,
        protocol="dcap",
    ):
        # Require at least enclave or signer measurement
        if (mr_enclave, mr_signer) == (None, None):
            raise TypeError("Need at least one of: mrenclave, mrsigner")

        self.mr_enclave = mr_enclave
        self.mr_signer = mr_signer
        self.isv_prod_id = isv_prod_id
        self.isv_svn = isv_svn

        self.allow_debug_enclave_insecure = allow_debug_enclave_insecure
        self.allow_outdated_tcb_insecure = allow_outdated_tcb_insecure
        self.allow_hw_config_needed = allow_hw_config_needed
        self.allow_sw_hardening_needed = allow_sw_hardening_needed

        # Only supports dcap for now
        if protocol != "dcap":
            raise ValueError("Only dcap verification supported")

        self.protocol = protocol

        # Load gramine ra_tls verify callback function once for all
        lib_ra_tls = ctypes.cdll.LoadLibrary("libra_tls_verify_dcap.so")
        """
        TODO
        The following call triggers a warning because it will be deprecated.
        Checked for using the ..._extended function but it uses enums.
        Need to sort out how to do enum types.
        """
        self._func_ra_tls_verify_callback = (
            lib_ra_tls.ra_tls_verify_callback_der
        )
        self._func_ra_tls_verify_callback.argtypes = (
            ctypes.c_char_p,
            ctypes.c_size_t,
        )
        self._func_ra_tls_verify_callback.restype = ctypes.c_int

    def _ra_tls_setenv(self, var, value, default=None):
        """
        Utils function for properly setting ra-tls environment variables.
        """
        if value in (None, False):
            if default is None:
                try:
                    del os.environ[var]
                except KeyError:
                    pass
            else:
                os.environ[var] = default
        elif value is True:
            os.environ[var] = "1"
        else:
            os.environ[var] = value

    def custom_verify_nonratls_callback(self, cert_bytes_der):
        return False

    def custom_verify_callback(self, mr_enclave, mr_signer, isv_prod_id, isv_svn, debug_flag):
        """
        Custom callback for inheritors to implement, allowing you to filter
        mr_enclave, mr_signer, etc. using custom logic, not just a single value.
        Leave the appropriate constructor args to their default values, e.g. "any"
        """
        return True

    def verify_ra_tls(self, cert_bytes_der):
        # Set environment variables for gramine verification function to use
        self._ra_tls_setenv("RA_TLS_MRENCLAVE", self.mr_enclave, "any")
        self._ra_tls_setenv("RA_TLS_MRSIGNER", self.mr_signer, "any")
        self._ra_tls_setenv("RA_TLS_ISV_PROD_ID", self.isv_prod_id, "any")
        self._ra_tls_setenv("RA_TLS_ISV_SVN", self.isv_svn, "any")

        self._ra_tls_setenv(
            "RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE",
            self.allow_debug_enclave_insecure,
        )
        self._ra_tls_setenv(
            "RA_TLS_ALLOW_OUTDATED_TCB_INSECURE",
            self.allow_outdated_tcb_insecure,
        )
        self._ra_tls_setenv(
            "RA_TLS_ALLOW_HW_CONFIG_NEEDED", self.allow_hw_config_needed
        )
        self._ra_tls_setenv(
            "RA_TLS_ALLOW_SW_HARDENING_NEEDED", self.allow_sw_hardening_needed
        )

        cert_info = RaTlsCertInfo(cert_bytes_der)

        if not cert_info.is_ratls:
            return self.custom_verify_nonratls_callback(cert_bytes_der)

        # Execute gramine callback function and check result
        ret = self._func_ra_tls_verify_callback(cert_bytes_der, len(cert_bytes_der))
        if ret < 0:
            raise AttestationError(ret)
        
        custom_verification_passed = self.custom_verify_callback(
            cert_info.mr_enclave,
            cert_info.mr_signer,
            cert_info.isv_prodid,
            cert_info.isv_svn,
            cert_info.debug_bit
        )

        if not custom_verification_passed:
            raise AttestationError(RaTlsVerifier.custom_verify_callback.__name__)
    
class RaTlsClient:
    def __init__(
        self,
        verifier,
        cert_file=None,
        key_file=None,
    ):
        self.verifier = verifier
        self.cert_file = cert_file
        self.key_file = key_file
    
    async def connect(self, loop, hostname, port):
        # Create an SSL context
        context = ssl._create_unverified_context()  # pylint: disable=protected-access
        if self.cert_file is not None:
            context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
            
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setblocking(False)

        await loop.sock_connect(raw_sock, (hostname, port))

        # Perform TLS handshake in an executor
        def do_handshake():
            ssock = context.wrap_socket(raw_sock, server_hostname=hostname)
            ssock.do_handshake()
            return ssock

        try:
            ssock = await loop.run_in_executor(None, do_handshake)
        except ssl.SSLError as e:
            raw_sock.close()
            raise ConnectionError(f"TLS handshake failed: {e}")

        # Verify enclave attestation with the provided verifier
        try:
            # NEVER SEND ANYTHING TO THE SERVER BEFORE THIS LINE
            self.verifier.verify_ra_tls(ssock.getpeercert(binary_form=True))
        except AttestationError:
            ssock.close()
            raise

        return ssock
    
class RaTlsServer:
    def __init__(
        self,
        server_cert,
        server_key,
        verifier,
    ):
        self.verifier = verifier
        self.server_cert = server_cert
        self.server_key = server_key
        self.context = None
        self.server_socket = None
        self.connections = dict()
        
    def __enter__(self):
        return self
    
    def __exit__(self, exec_type, exec_val, exec_tb):
        self.close()
            
    def close(self):
        if self.server_socket is not None:
            self.server_socket.close()
    
    def bind_and_listen(self, hostname, port):
        # We need to use OpenSSL because mutual tls doesn't want to work
        # with RA-TLS certificates using the built-in ssl module. 
        # context.set_verify is more flexible for our use case. It's not 
        # as scalable though because it doesn't have native asyncio support.
        self.context = SSL.Context(SSL.TLS_SERVER_METHOD)
        self.context.use_privatekey_file(self.server_key)
        self.context.use_certificate_chain_file(self.server_cert)

        # Enforce client certificates
        self.context.set_verify(
            SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.verify_callback
        )

        # Start the server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)
        self.server_socket.bind((hostname, port))
        self.server_socket.listen()

    async def _handle_client(self, loop, client_sock, client_addr, handle_client):
        if self.context is None: return
        # Wrap the raw socket with OpenSSL
        tls_conn = SSL.Connection(self.context, client_sock)
        tls_conn.set_accept_state()

        try:
            await loop.run_in_executor(None, tls_conn.do_handshake)
            cert = tls_conn.get_peer_certificate()
            await handle_client(tls_conn, client_addr, RaTlsCertInfo(None if cert is None else cert.to_cryptography().public_bytes(encoding=serialization.Encoding.DER)))
        finally:
            tls_conn.shutdown()
            tls_conn.close()
            self.connections.pop(client_addr)  # remove active connection task

    def verify_callback(self, connection, x509_cert, errno, depth, preverify_ok):
        """Custom certificate verification callback."""
        if depth == 0:  # Only check the end-entity certificate
            try:
                self.verifier.verify_ra_tls(x509_cert.to_cryptography().public_bytes(encoding=serialization.Encoding.DER))
            except AttestationError:
                return False
            return True
        return preverify_ok

    async def accept(self, handle_client_callback, loop=None):
        if self.server_socket is None: raise ConnectionError()
        loop = asyncio.get_event_loop() if loop is None else loop
        client_sock, client_addr = await loop.run_in_executor(None, self.server_socket.accept)
        print(f"Accepted connection from {client_addr}")
        return (client_addr, asyncio.create_task(self._handle_client(loop, client_sock, client_addr, handle_client_callback)))
    
    async def serve(self, handle_client_callback, loop=None):
        try:
            while True:
                try:
                    addr, task = await self.accept(handle_client_callback, loop)
                    self.connections[addr] = task
                    # await asyncio.gather(*self.connections.values())  # unreachable
                except TimeoutError:
                    continue
        except CancelledError:
            for task in self.connections.values():
                task.cancel()  # cancel remaining tasks explicitly
            await asyncio.gather(*self.connections.values(), return_exceptions=True)




