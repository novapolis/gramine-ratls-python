# Gramine RATLS Python Wrapper Package

This package is a Python wrapper around the Gramine binary library for Intel SGX attestation and verification with RATLS.

In addition to the package, the Github repository also provides a toy example of a client and server implementation. The server enclave is built using a "Graminized" Docker image running a Fastapi app.

The sections below aim to provide as much context as possible for the uninitiated, the guide hopefully provides enough information and relevant links to be used as a starting point.

A word of caution: The guide focuses on our toy example but the principles apply to any vanilla Python server that can use a TLS cerficate and setup a TLS connection with a client. Some of the setup steps for Gramine and SGX are specific to an infrastructure using the DCAP protocol for remote attestation. If a machine is correctly configured to use the EPID protocol, adjusting the gramine manifest to run the toy example should be relatively straightforward.

### High level intended Use

The general workflow for building a server container image and running the toy example is outlined here:

- Build a server Docker image containing the server python script. Before starting the fastapi app, the python server creates the ra-tls certificate and corresponding key using the python gramine-ratls package and writes them to disk. The generated files will be used by uvicorn (the python server library) as server certificate files and provide the attestation to the client.
- "Graminize" the docker image with the GSC tool (Gramine Shielded Container) to run the fastapi server inside an SGX enclave.
- Run the client as a local Python (or else) program, no SGX involved. The client verifies the attestation quote using the gramine-ratls python package.

### Installation

Install the python package from PyPi using

```[python]
pip install gramine-ratls
```

For using the source files in this repo, use 

```[python]
pip install -e .
```

For installing all the Intel SGX and Gramine dependencies, see the installation and setup section below.

## Introduction and General Information

### Gramine and Intel SGX

We use [Gramine](https://gramineproject.io/) to run the server inside an Intel SGX enclave.

Let us (very briefly and on a very high level) explain how Gramine works. Initially, SGX enclave were meant to be developped using the SGX development kit. An application would be "SGX aware" and be split into a "trusted" part, running inside SGX, and an "untrusted" part, running outside SGX. An application starts with untrusted code, and calls to EENTER and EEXIT instructions are required to enter/exit the enclave. The instruction set available to enclave code is very limited (e.g. no priviledged instructions, which means no system calls in the Linux world). The development of SGX aware applications is usually done in compiled languages such as C++ and leverages the Intel provided SGX Software Development Kit.

Gramine started as a research project, with the goal of running entire legacy applications inside SGX enclaves. Gramine comes in the form of a Library OS (LibOS) that can be seen as the operating system that runs the target application. The LibOS intercepts all application requests that are made to the host OS (most of these would otherwise error since SGX does not allow priviledged instructions.), and either implements them itself or transfers them to the host OS and sanitizes the resutls. Gramine implements a Platform Adaptation Layer (PAL) for interfacing between the LibOS and the host OS. For more information on Intel SGX and Gramine, it is highly recommended to read the Gramine documentation in details. A good starting point is [the Gramine Introduction to SGX](https://gramine.readthedocs.io/en/stable/sgx-intro.html) and the [Gramine features page](https://gramine.readthedocs.io/en/stable/sgx-intro.html).

Additionnally to protecting running code from adversaries with priviledged access to the host OS or physical machine, SGX also allows to verify the integrity of an application's trusted part, even remotely. On a very very high level (again), enclave attestation works as follows: an enclave produces a quote (comprising code measurements, enclave author, hardware measurements, etc.) that is transfered to the remote verifier. The remote verifier then verifies the quote with the help of Intel (or the cloud provider's) quote verification services. Gramine provides some higher level functionality to complete the enclave attestation/verification process. We will use ra-tls and focus on this option only. The idea behind ra-tls is to include the attestation quote inside the standard server TLS certificate. When the remote verifier connects to the enclave (the server), it extracts the quote from the server TLS certificate and verifies it before finishing the TLS connection handshake. For more information about this, it is highly recommended to read the [Gramine Attestation and Secret Provisioning](https://gramine.readthedocs.io/en/stable/attestation.html) page.

## Python package for gramine ra-tls related functionality

As stated above, the server uses ra-tls to attest its code and runing environment. Before starting the fastapi app, the python server must create the ra-tls certificate and corresponding key using Gramine ra-tls binary libraries and write them to disk. These will be used by uvicorn as server certificate and provide the attestation to the client.

Gramine provides binary libraries for generating ra-tls certificates and verifying them. These are meant to be linked with applications built in compiled languages such as C. The Gramine repository contains such an example application with the [ra-tls-mbedtls example](https://github.com/gramineproject/gramine/tree/master/CI-Examples/ra-tls-mbedtls). Because we are using a fastapi application written in Python, as well as Python clients, we have to call the Gramine ra-tls functions directly from Python. Such an example is not yet provided in the Gramine repository, hence why we created this package.

This package provides functions for generating ra-tls certificates and verifying them in Python. It is built on top of and requires the Gramine ra-tls binary libraries that come with Gramine. Some of the code is heavily inspired from the C implementation of the Gramine gramine-ratls utility as well as the python code in [this](https://github.com/gramineproject/gramine/compare/woju/gramine-ratls-client) PR from the official Gramine repo.

Note on the gramine-ratls CLI utility tool from Gramine: As is demonstrated in the [ra-tls-nginx example](https://github.com/gramineproject/gramine/tree/master/CI-Examples/ra-tls-nginx), Gramine provides the gramien-ratls utility to generate ra-tls certificates for SGX "unaware applications". The gramine-ratls tool is used as entrypoint for the LibOS. It generates the ra-tls x.509 key and certificate (in pem or der format) before starting the main application itself. Using this tool requires changes to the Gramine manifest, namely libos.entrypoint and loader.argv, of which the latter is not supported in GSC. Indeed, GSC automatically generates an arguments file from the source Docker image's entrypoint/cmd and uses loader.argv_src_file, which is mutually exclusive with loader.argv. One could patch GSC to take this into account: loader.argv_src_file should be removed if loader.argv is manually specified by the user. TBD.

### Gramine Shielded Containers

Gramine Shielded Containers (GSC) is used to "Graminize" a standard Docker image so that its content can be executed within an SGX enclave. The goal here is to simplify the process of running applications with Gramine even more and by enabling a simple transformation of existing container images into images that run their process within Intel SGX enclaves.

## Installation and Setup

### Gramine and SGX Tools

Let's continue our journey by installing Gramine:

- Install Gramine by following the instructions [here](https://gramine.readthedocs.io/en/latest/installation.html#ubuntu-22-04-lts-or-20-04-lts).

A few more steps and Intel SGX tools are required, see [here](https://gramine.readthedocs.io/en/latest/sgx-setup.html) for more content on this. The code in this repo does not directly interact with most of these components (only indirectly through Gramine, but a bit of context is good for general understanding):
- Create an SGX signing key with the command `gramine-sgx-gen-private-key`. This will write a pem key to `$HOME/.config/gramine/enclave-key` by default. Such a key is needed to sign enclaves at creation. Resulting measurements from this operation are used to verify enclave attestations once the enclave is deployed.
- Intel PSW (Platform SoftWare): (Note: this is already done on Azure SGX VMs). This provides several SGX functionalities from loading and initializing SGX enclaves to management of so-called "architectural" enclaves. It runs as a Linux service (aesm_service for Application Enclave Services Manager). For information, the interface to this service is through a socket located at `/var/run/aesmd/aesm.socket` (this will be usefull later, because we need to provide this socket to the server container). TODO: check if we had to install this + link to instructions
- Intel DCAP library: This binary library provides functionality for dcap quote generation and verification. TODO check if we had to install this + instructions
- Intel QPL library: This binary library provides functionality for the communication with DCAP verification services. TODO add qpl config + difference with azure_dcap library.

At this stage, it is highly recommended to check the setup by running the python `sgx-quote.py` example from the Gramine repository (see [here](https://github.com/gramineproject/gramine/tree/master/CI-Examples/python)). This will also help understand more about how an application is "graminized", The Gramine CLI tool `is-sgx-available` can also be of good use to verify the setup.

### Gramine Shielded Containers

As stated above, this tool is used to "Graminize" a standard Docker image so that its content can be executed within an SGX enclave.

If the reader has already played with the Gramine CI-Examples linked above, they should have some understanding of how to configure the process of "graminizing" an application with the manifest file and how to run it with Gramine-SGX. GSC automates this entire process for standard Docker images by creating a manifest file with the correct configuration (entrypoint, sgx trusted files, etc.) and a new image containing the required application files, a Gramine install as well as the signed enclave.

The GSC tool comes as a python script. It is installed by cloning [this](https://github.com/gramineproject/gsc) Git repository. Documentation for the tool as well as installation instructions can be found [here](https://gramine.readthedocs.io/projects/gsc/en/latest/).

### Python Package

Install the python package from PyPi using

```[python]
pip install gramine-ratls
```

For using the source files in this repo, use 

```[python]
pip install -e .
```

## Toy Example

To illustrate the usage of the python gramine-ratls library, we provide an example server and client implementation.

### Server

The server is located in `example/src/uvicorn_serve.py`: it calls into the gramine-ratls package for generating the ra-tls certificates and then starts the fastapi app in `example/src/app.py` with the required SSL/TLS configurations.

Note that the uvicorn server MUST run as a single process, hence why the number of workers is set to 1 and the reload option disabled. Gramine implements multiprocessing by starting separate enclaves for each process and having them communicate through secure channels. While Gramine enables mounting memory backed temporary file systems (tmpfs) within a single enclave, these are not persisted across multiple enclaves. Saving the ra-tls certificates in one process, but not being able to recover them in the second one breaks our application's ability to attest itself. Another option for writing files to disk is using the sgx.allowed files option in Gramine. This however uses the host OS's file system and is thus not safe.

To build the base docker image, use

```[bash]
docker build -t ratls-test .
```

The GSC configuration, the server's manifest file and the Python requirements file for GSC are all located in `example/gsc-configs` and it is assumed that GSC is manually cloned under `example/gsc-configs/gsc`. Finally, it is also expected that an SGX signing key was generated with the `gramine-sgx-gen-private-key` and saved to `/home/azureuser/.config/gramine/enclave-key.pem` (default behaviour).

To generate the graminized and signed Docker image for the server, run the following only once:

```
./gsc build-gramine --rm --no-cache -c ../config.yaml gramine-base
```

This will build the base gramine image, without any application specific files. The next steps will use this base image as a starting point, avoiding the rebuild of the base image everytime they are executed.

```
cd gsc-configs/gsc/

./gsc build -c ../config.yaml --rm ratls-test ../gramine.manifest

./gsc sign-image -c ../config.yaml  ratls-test /home/azureuser/.config/gramine/enclave-key.pem

cd ../../
```

To print information about the enclave image, use

```
./gsc info-image gsc-ratls-test
```

For cleaning up all generated docker images (except gramine-base), use 

```
docker image rm gsc-ratls-test gsc-ratls-test-unsigned:latest ratls-test:latest
```

### Client

The client is implemented in `example/src/client.py`. It contains an implementation of a dummy python class for making requests to the server. The dummy client internally wraps the `Client` class provided by the gramine_ratls package (see `src/gramine_ratls/verify.py`) The gramine_ratls python client loads the required verification callback function from the Gramine ratls binary library and performs the verification at every connection/request. Its `get` and `post` functions return a python `http.HTTPResponse` object.

__Important__: Before using the client, update the main function of the `example/src/client.py` file with the correct `mr_signer` and `mr_enclave` of the graminized image with `./gsc info-image gsc-ratls-test`.


### Running

Start the server with 

```
docker run --device=/dev/sgx_enclave -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket -p 8000:8000 --rm gsc-ratls-test
```

A few things happen here:
- The SGX device is "forwarded" to the container
- The aesm socket is mounted into the container for Gramine to be able to interact with the aesm service.
- Finally, the server port is exposed.

The client is finally tested by running
```
python client.py
```

To kill all running docker containers, run 

```
docker kill $(docker ps -a -q)
```

### Doing things a bit faster with build.sh

The `build.sh` script automates the removal of old images and the rebuilding, graminizing and signing of the server image. You have to manually edit the `client.py` file and start the server and client applications.







