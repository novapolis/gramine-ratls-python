"""
Largely inspired from
https://github.com/gramineproject/gramine/commit/1a1869468aef7085d6c9d722adf9d1d0484e1b4c # noqa: E501
"""

import ctypes
import os
import ssl
from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import socket

class AttestationError(Exception):
    pass


class Verifier:
    """
    A TLS client or server for RA-TLS server that verifies the
    server provided RA-TLS certificate for every request
    it makes.
    """
    def __init__(
        self,
        mr_enclave,
        mr_signer,
        isv_prod_id,
        isv_svn,
        allow_debug_enclave_insecure,
        allow_outdated_tcb_insecure,
        allow_hw_config_needed,
        allow_sw_hardening_needed,
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

    def _verify_ra_tls_cb(self, cert):
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

        # Execute gramine callback function and check result
        ret = self._func_ra_tls_verify_callback(cert, len(cert))
        if ret < 0:
            raise AttestationError(ret)


class RaTlsClient:
    def __init__(
        self,
        mr_enclave,
        mr_signer,
        isv_prod_id,
        isv_svn,
        allow_debug_enclave_insecure,
        allow_outdated_tcb_insecure,
        allow_hw_config_needed,
        allow_sw_hardening_needed,
        protocol="dcap",
    ):
        self.verifier = Verifier(
            mr_enclave,
            mr_signer,
            isv_prod_id,
            isv_svn,
            allow_debug_enclave_insecure,
            allow_outdated_tcb_insecure,
            allow_hw_config_needed,
            allow_sw_hardening_needed,
            protocol,
        )
    
    def connect(self, hostname, port):
        # Create TLS connection
        context = (
            ssl._create_unverified_context()
        )  # pylint: disable=protected-access
        
        # Connect to the server and initiate the TLS handshake
        sock = socket.create_connection((hostname, port))
        ssock = context.wrap_socket(sock, server_hostname=hostname)

        # Verify enclave attestation with proper callback function
        try:
            # NEVER SEND ANYTHING TO THE SERVER BEFORE THIS LINE
            self.verifier._verify_ra_tls_cb(ssock.getpeercert(binary_form=True))
        except AttestationError:
            ssock.close()
            raise
        
        return ssock
    
class MutualRaTlsClient:
    def __init__(
        self,
        client_cert,
        client_key,
        mr_enclave,
        mr_signer,
        isv_prod_id,
        isv_svn,
        allow_debug_enclave_insecure,
        allow_outdated_tcb_insecure,
        allow_hw_config_needed,
        allow_sw_hardening_needed,
        protocol="dcap",
    ):
        self.client_cert = client_cert
        self.client_key = client_key
        self.verifier = Verifier(
            mr_enclave,
            mr_signer,
            isv_prod_id,
            isv_svn,
            allow_debug_enclave_insecure,
            allow_outdated_tcb_insecure,
            allow_hw_config_needed,
            allow_sw_hardening_needed,
            protocol,
        )
    
    def connect(self, hostname, port):
        # Create TLS connection
        context = (
            ssl._create_unverified_context()
        )  # pylint: disable=protected-access
        context.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)
        
        # Connect to the server and initiate the TLS handshake
        sock = socket.create_connection((hostname, port))
        ssock = context.wrap_socket(sock, server_hostname=hostname)

        # Verify enclave attestation with proper callback function
        try:
            # NEVER SEND ANYTHING TO THE SERVER BEFORE THIS LINE
            self.verifier._verify_ra_tls_cb(ssock.getpeercert(binary_form=True))
        except AttestationError:
            ssock.close()
            raise
        
        return ssock
    
class RaTlsServer:
    def __init__(
        self,
        server_cert,
        server_key,
        mr_enclave,
        mr_signer,
        isv_prod_id,
        isv_svn,
        allow_debug_enclave_insecure,
        allow_outdated_tcb_insecure,
        allow_hw_config_needed,
        allow_sw_hardening_needed,
        protocol="dcap",
    ):
        self.server_cert = server_cert
        self.server_key = server_key
        self.verifier = Verifier(
            mr_enclave,
            mr_signer,
            isv_prod_id,
            isv_svn,
            allow_debug_enclave_insecure,
            allow_outdated_tcb_insecure,
            allow_hw_config_needed,
            allow_sw_hardening_needed,
            protocol,
        )
        self.server_socket = None
        self.tls_socket = None
        
    def __enter__(self):
        return self
    def __exit__(self, exec_type, exec_val, exec_tb):
        self.close()
            
    def close(self):
        if self.tls_socket is not None:
            self.tls_socket.close()
    
    def bind_and_listen(self, hostname, port):
        context = SSL.Context(SSL.TLS_SERVER_METHOD)
        context.use_privatekey_file(self.server_key)
        context.use_certificate_chain_file(self.server_cert)

        # Enforce client certificates
        context.set_verify(
            SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.verify_callback
        )

        # Start the server
        self.server_socket = socket.socket()
        self.tls_socket = SSL.Connection(context, self.server_socket)

        self.tls_socket.bind((hostname, port))
        self.tls_socket.listen()

    def verify_callback(self, connection, x509_cert, errno, depth, preverify_ok):
        """Custom certificate verification callback."""
        if depth == 0:  # Only check the end-entity certificate
            try:
                self.verifier._verify_ra_tls_cb(x509_cert.to_cryptography().public_bytes(encoding=serialization.Encoding.DER))
            except AttestationError:
                return False
            return True
        return preverify_ok

    def accept(self):
        conn, addr = self.tls_socket.accept()
        
        return (conn, addr)