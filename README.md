# TCP/IP Client-Server Communication Tool

## Overview
The TCP/IP Client-Server Communication Tool is a custom-built project designed to facilitate networking computations and client-server interactions. This tool allows clients to perform various network-related tasks by communicating with a centralized server. The server processes client requests, performs calculations, and returns the results, making it a valuable learning experience in network programming, Docker containerization, and protocol design.

---

## Features
- **Network Calculations**:  
  - Calculate network numbers, broadcast addresses, and subnet masks in Dotted Decimal Notation (DDN) using CIDR (Classless Inter-Domain Routing) notation.
  - Perform binary-to-decimal conversion for IP addressing tasks.  

- **IP Address Analysis**:  
  - Determine if two IP addresses belong to the same subnet.  
  - Verify whether an IP address is public or private.  

- **Task Validation**:  
  - Clients receive tasks from the server and submit results.  
  - The server evaluates the results and provides feedback.  

- **Containerized Environment**:  
  - Docker is used to simulate client-server interaction within isolated containers.  
  - Seamless deployment and testing across multiple Docker containers.

---

## Project Structure
. ├── docker-compose.yml # Docker configuration for environment setup ├── purgeAll.sh # Cleanup script to remove Docker containers ├── TCPClient.py # Basic client-side implementation ├── TCPClientNew.py # Extended client with additional features ├── TCPServerNew.py # Advanced server with task validation and networking functions └── TCPServerSelect.py # Select-based server for handling multiple clients simultaneously
---

## Learning Outcomes
- **Networking Fundamentals**:  
  Learned the essentials of subnetting, CIDR, IP classes, and broadcast calculations.  

- **Socket Programming**:  
  Developed hands-on experience in Python socket programming for communication between clients and servers.  

- **Containerization**:  
  Utilized Docker to create isolated environments for deploying and testing the client-server model.  

- **Problem Solving**:  
  Addressed challenges such as IP miscalculations, binary conversion errors, and task handling through iterative debugging and testing.

---

## Challenges Faced
- **Subnetting Complexity**:  
  Understanding and implementing subnetting rules required deep research and testing.  

- **Protocol Design**:  
  Designing a clear and efficient protocol to handle client requests and server responses was a significant learning curve.  

- **Debugging**:  
  Testing the correctness of IP-related computations involved extensive use of external subnet calculators and debugging tools.

---

## How It Works
1. **Client-Server Communication**:  
   - The client initiates communication by sending identification data to the server.  
   - The server responds with available task options.  

2. **Task Selection**:  
   - Clients can choose tasks such as calculating network numbers, broadcast addresses, or verifying subnet information.  

3. **Validation and Feedback**:  
   - The server evaluates the client's submitted answers and provides feedback indicating success or failure.

---

## How to Run the Project

### Prerequisites
- Docker installed on your machine
- Python 3.x environment

---

### Setup
1. **Clone the Repository**  
   ```bash
   git clone https://github.com/Golani51/tcp-ip-tool
   cd tcp-ip-tool
1. **Clone the Repository**
docker-compose up -d
2. **Access Docker Containers**
docker exec -it H1 /bin/bash
docker exec -it H2 /bin/bash
docker exec -it H3 /bin/bash
3. **Copy Files to Containers**
docker cp TCPServerNew.py H1:/tmp/TCPServerNew.py
docker cp TCPClientNew.py H2:/TCPClientNew.py
docker cp TCPClientNew.py H3:/TCPClientNew.py
4. **Run the Server and Client**
python3 /tmp/TCPServerNew.py
python3 /TCPClientNew.py
##Common Docker Commands**
**Stop All Containers**
docker-compose down
**Remove All Containers**
./purgeAll.sh
**List Running Containers**
docker ps
## Author
**Benjamin Maher**  
- [GitHub Profile](https://github.com/Golani51)  
- [LinkedIn](https://linkedin.com/in/benjamin-maher)  
- 📧 [Email Me](mailto:benjamin.maher813@gmail.com)  
