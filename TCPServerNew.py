#TCPserver
import sys
from socket import *
from select import *
import ipaddress
import time
import random
import struct
client_states = {}  # Map sockets to client states
# function to check if an IP address is private or public
# this is used in my personal question for choice "e"
def is_private_ip(ip):
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        if ip_obj.is_private:
            return "PRIVATE"
        else:
            return "PUBLIC"
    except ipaddress.AddressValueError:
        return "ERROR"
# this function creates a random IP address with a subnet mask
def create_random_ip_with_mask():
    # Helper function to generate a single random octet
    def generate_octet(seed=None):
        random.seed(seed if seed is not None else time.time())
        return random.randint(0, 255)

    # Generate each octet separately
    octet1 = random.randint(1, 255)  # Ensure the first octet is valid for an IP address
    octet2 = generate_octet(octet1)  # Seeded with the first octet
    octet3 = generate_octet(octet2)  # Seeded with the second octet
    octet4 = generate_octet(octet3)  # Seeded with the third octet

    # Construct the IP address in parts
    ip_parts = [str(octet1), str(octet2), str(octet3), str(octet4)]
    ip = '.'.join(ip_parts)  # Join octets into a dotted decimal format

    # Generate the subnet mask
    def generate_subnet_mask():
        mask_list = list(range(8, 31))  # List of valid CIDR masks
        mask = random.choice(mask_list)  # Choose randomly from the list
        return mask

    mask = generate_subnet_mask()

    # Construct final output
    full_address = "/".join([ip, str(mask)])
    return full_address
# this function creates a random IP address
def create_random_ip():
    # generate an octet
    def generate_octet(previous_octet=None):
        # Create a custom random range for each octet
        if previous_octet is None:
            return random.randint(1, 255)  # First octet must be valid
        else:
            offset = (previous_octet % 128) + 1 
            return (random.randint(0, 255) + offset) % 256  # Wrap around to keep valid octet

    # Generate the octets
    octet1 = generate_octet()
    octet2 = generate_octet(octet1)
    octet3 = generate_octet(octet2)
    octet4 = generate_octet(octet3)

    # store octets in a dictionary
    ip_parts = {f"octet{i+1}": octet for i, octet in enumerate([octet1, octet2, octet3, octet4])}

    # Assemble the IP address
    ip_address = f"{ip_parts['octet1']}.{ip_parts['octet2']}.{ip_parts['octet3']}.{ip_parts['octet4']}"

    # mask generator
    def generate_mask():
        # determining the range of masks
        lower_bound = 8
        upper_bound = 30
        mask_pool = list(range(lower_bound, upper_bound + 1))  # Pool of valid CIDR masks
        selected_mask = random.choice(mask_pool)  # Randomly pick from the pool
        return selected_mask

    # Generate the mask
    subnet_mask = generate_mask()

    # Return the final address
    ip_with_mask = "{}/{}".format(ip_address, subnet_mask)
    return ip_with_mask
# this function is used to solve network number with ip mask
def calculate_the_network_number(ip_mask):
    # Split the input string into IP and mask
    def extract_ip_and_mask(input_str):
        parts = input_str.split('/')
        if len(parts) != 2:
            raise ValueError("Invalid IP/mask format")
        return parts[0], parts[1]

    # Validate and convert the IP and mask into a network object
    def validate_and_convert_to_network(ip, mask):
        try:
            network_obj = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            return network_obj
        except ValueError as e:
            raise ValueError(f"Invalid IP or mask: {e}")

    # Format the network address and mask into a single string
    def format_network_address(network_obj):
        address = str(network_obj.network_address)
        mask = str(network_obj.prefixlen)
        return "{}/{}".format(address, mask)

    # Extract IP and mask from input
    ip, mask = extract_ip_and_mask(ip_mask)

    # Convert to network object
    network = validate_and_convert_to_network(ip, mask)

    # Format and return the network address with the mask
    result = format_network_address(network)
    return result
# this function is used to figure our the network number
def solve_the_network_number(ip_with_mask):
    # Split the input into IP and mask
    def split_ip_and_mask(input_str):
        parts = input_str.split('/')
        if len(parts) != 2:
            raise ValueError("Input must be in the format 'IP/Mask'")
        return parts[0], parts[1]

    # Validate and create a network object from the IP and mask
    def create_network_object(ip, mask):
        try:
            network_obj = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            return network_obj
        except ValueError as e:
            raise ValueError(f"Invalid IP or mask: {e}")

    # Format the network address as a string
    def format_network_address(network_obj, mask):
        address = str(network_obj.network_address)
        return "{}/{}".format(address, mask)

    # Extract IP and mask
    ip, mask = split_ip_and_mask(ip_with_mask)

    # Create a network object from the IP and mask
    network = create_network_object(ip, mask)

    # Format the final network address
    result = format_network_address(network, mask)
    return result
# this function is used to solve the broadcase address
def broadcast_network_address_solver(ip_with_mask):
    # Split the input into IP and mask
    def split_ip_and_mask(input_str):
        parts = input_str.split('/')
        if len(parts) != 2:
            raise ValueError("Input must be in the format 'IP/Mask'")
        return parts[0], parts[1]

    # Validate and create a network object from the IP and mask
    def create_network_object(ip, mask):
        try:
            network_obj = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            return network_obj
        except ValueError as e:
            raise ValueError(f"Invalid IP or mask: {e}")

    # Extract the broadcast address from the network object
    def get_broadcast_address(network_obj):
        return str(network_obj.broadcast_address)

    # Extract IP and mask from the input
    ip, mask = split_ip_and_mask(ip_with_mask)

    # Create a network object
    network = create_network_object(ip, mask)

    # Retrieve and return the broadcast address
    broadcast_address = get_broadcast_address(network)
    return broadcast_address
# this function is used to figure our the netmask in DDN
def solve_netmask_in_dotted_deciaml_notation(mask):
    # Validate the mask input
    def validate_mask(mask_input):
        try:
            mask_int = int(mask_input)
            if mask_int < 0 or mask_int > 32:
                raise ValueError("Mask must be between 0 and 32")
            return mask_int
        except ValueError as e:
            raise ValueError(f"Invalid mask value: {e}")

    # Create a network object using the mask
    def create_network_from_mask(valid_mask):
        try:
            network_obj = ipaddress.IPv4Network(f"0.0.0.0/{valid_mask}", strict=False)
            return network_obj
        except ValueError as e:
            raise ValueError(f"Failed to create network object: {e}")

    # Extract and format the netmask from the network object
    def extract_netmask(network_obj):
        return str(network_obj.netmask)

    # Validate the input mask
    validated_mask = validate_mask(mask)

    # Create a network object from the mask
    network = create_network_from_mask(validated_mask)

    # Extract and return the netmask in dotted decimal notation
    netmask = extract_netmask(network)
    return netmask
# this function works by creating a random pair of IP addresses that gets used for the same network check question
def make_random_pair_of_ips():
    # Generate the base IP address
    def generate_base_ip():
        octet1 = random.randint(1, 255)  # Ensure the first octet is valid
        octet2 = random.randint(0, 255)
        octet3 = random.randint(0, 255)
        return f"{octet1}.{octet2}.{octet3}"

    # Generate a random IP with the given base and range
    def generate_ip_with_range(base, start, end):
        try:
            last_octet = random.randint(start, end)
            ip = f"{base}.{last_octet}/24"
            return ip
        except ValueError as e:
            raise ValueError(f"Failed to generate IP: {e}")

    # Create a pair of IPs using the base and distinct ranges
    def create_ip_pair(base):
        ip1 = generate_ip_with_range(base, 1, 127)
        ip2 = generate_ip_with_range(base, 128, 254)
        return ip1, ip2

    # Generate the base IP
    base_ip = generate_base_ip()

    # Generate the IP pair
    ip1, ip2 = create_ip_pair(base_ip)

    # Return the IPs as a single formatted string
    return f"{ip1} {ip2}"
# this function is used to check if two addresses are in the same network
def verify_if_network_is_the_same(addresses):
    # Split the input addresses into two parts
    def split_addresses(address_input):
        parts = address_input.split(' ')
        if len(parts) != 2:
            raise ValueError("Input must contain exactly two addresses separated by a space")
        return parts[0], parts[1]

    # Convert each address into a network object
    def convert_to_network(address):
        try:
            network_obj = ipaddress.IPv4Network(address, strict=False)
            return network_obj
        except ValueError as e:
            raise ValueError(f"Invalid network address: {e}")

    # Compare the network addresses of two network objects
    def compare_networks(network1, network2):
        if network1.network_address == network2.network_address:
            return "TRUE"
        else:
            return "FALSE"

    # Attempt to process the input addresses
    try:
        # Split the addresses
        address1, address2 = split_addresses(addresses)

        # Convert to network objects
        network1 = convert_to_network(address1)
        network2 = convert_to_network(address2)

        # Compare the two networks
        result = compare_networks(network1, network2)
        return result
    except ValueError:
        return "ERROR"
# create a variable to hold session summary information
session_summary = {}  # Map socket to summary data
def send_session_summary(rsock):
    if rsock in session_summary:
        summary = session_summary[rsock]
        summary_msg = (
            f"Session Summary:\n"
            f"Identity: {summary.get('identity', 'Unknown')}\n"
            f"Total Questions: {summary.get('total', 0)}\n"
            f"Correct Answers: {summary.get('correct', 0)}\n"
            f"Thank you for participating!\n"
        )
        print(f"Sending session summary to {rsock.getpeername()}: {summary_msg}")  # Debug
        rsock.send(summary_msg.encode('ascii'))

# Function to handle client options
def main_menu_of_user_pick(option, rsock):
    correct = False
    if option == "a":
        question = create_random_ip_with_mask()
        rsock.send(f"Compute Network Number for {question}\n".encode('ascii'))
        answer = rsock.recv(1000).decode('ascii').strip()
        expected = solve_the_network_number(question)
        correct = (answer == expected)
    elif option == "b":
        question = create_random_ip_with_mask()
        rsock.send(f"Compute Broadcast Address for {question}\n".encode('ascii'))
        answer = rsock.recv(1000).decode('ascii').strip()
        expected = broadcast_network_address_solver(question)
        correct = (answer == expected)
    elif option == "c":
        mask = str(random.randint(8, 30))
        rsock.send(f"Compute Netmask in DDN for /{mask}\n".encode('ascii'))
        answer = rsock.recv(1000).decode('ascii').strip()
        expected = solve_netmask_in_dotted_deciaml_notation(mask)
        correct = (answer == expected)
    elif option == "d":
        question = make_random_pair_of_ips()
        rsock.send(f"Check if {question} are in the same network.\n".encode('ascii'))
        answer = rsock.recv(1000).decode('ascii').strip()
        expected = verify_if_network_is_the_same(question)
        correct = (answer == expected)
    elif option == "e":
        ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        rsock.send(f"Is the IP {ip} PRIVATE or PUBLIC?\n".encode('ascii'))
        answer = rsock.recv(1000).decode('ascii').strip().upper()
        expected = is_private_ip(ip)
        correct = (answer == expected)
    else:
        rsock.send("ERROR: Invalid Option Selected.\n".encode('ascii'))
        return False
    
    # Update session summary
    if rsock in session_summary:
        session_summary[rsock]["total"] += 1
        if correct:
            session_summary[rsock]["correct"] += 1

    # Send feedback and transition back to menu
    if answer == expected:
        rsock.send("SUCCESS\n".encode('ascii'))
    elif expected == "ERROR":
        rsock.send("ERROR: Invalid Input Format.\n".encode('ascii'))
    else:
        rsock.send(f"FAIL: Correct answer is {expected}\n".encode('ascii'))
    return True

# function that handles updating when processing messages
def process_client_message(rsock, message):
    state = client_states.get(rsock, {}).get("state", "menu")
    print(f"Processing message from {rsock.getpeername()}: {message} in state: {state}")

    if state == "menu":
        # Handle valid menu options
        if message in ["a", "b", "c", "d", "e"]:
            client_states[rsock]["state"] = "processing"
            if not main_menu_of_user_pick(message, rsock):
                rsock.send("Error: Invalid input. Please try again.".encode('ascii'))
            else:
                # After processing, transition back to menu state
                client_states[rsock]["state"] = "menu"
                #rsock.send("\n--- Menu ---\n".encode('ascii'))
        elif message == "f":
            send_session_summary(rsock)  # Send summary
            rsock.send("Exiting session. Goodbye!\n".encode('ascii'))
            clean_up_client(rsock)  # Then clean up

        else:
            rsock.send("Error: Invalid option. Please select a valid choice.".encode('ascii'))
    elif state == "processing":
        # Invalid case: Message during question processing
        rsock.send("Error: You are already processing a question. Please wait.".encode('ascii'))
    else:
        rsock.send("Error: Unknown state.".encode('ascii'))

# function to handle cleaning up client
def clean_up_client(rsock):
    if rsock in csocks:
        csocks.remove(rsock)
    if rsock in client_states:
        del client_states[rsock]
    if rsock in last_active:
        del last_active[rsock]  # Ensure timeout tracking is removed
    try:
        rsock.close()
    except OSError as e:
        print(f"Error closing socket: {e}")
    print(f"Cleaned up client: {rsock}")

# function to handle recieving identity from user
def identity(rsock):
    while True:
        smsg = "IDENTITY:"
        print("Sending: " + smsg)
        rsock.send(smsg.encode('ascii'))
        rmsg = rsock.recv(1000).decode('ascii').strip()
        if rmsg:
            print(f"Rcvd valid ID from {rsock.getpeername()}: {rmsg}")
            session_summary[rsock] = {"total": 0, "correct": 0, "identity": rmsg}  # Initialize here
            return True
        else:
            print(f"Error: Blank ID received from {rsock.getpeername()}. Prompting again.")
            rsock.send("ERROR: ID cannot be blank.\n".encode('ascii'))

# main function
if __name__ == "__main__":
    server = sys.argv[1]
    port = int(sys.argv[2])

    # Create a listening socket that will wait for new connections
    lsock = socket(AF_INET, SOCK_STREAM)
    lsock.bind((server, port))
    lsock.listen(5)
    # Create a list which will keep track of accepted connections
    csocks = []
    last_active = {}
    #session inactivity timeout
    timeout = 600 # 10 minutes
    
    print(f"Server listening on {server}:{port}")

    while True:
        # Identify which sockets are ready to be worked upon
        rl, wl, el = select([lsock] + csocks, [], csocks, timeout)

        if not (rl or wl or el):
            print("select() call timed out for", timeout, "seconds")
            continue
        
        # Close all the sockets on which error has occurred
        for esock in el:
            print("Closed", esock.getpeername())
            esock.close()
            csocks.remove(esock)
        
        # Check for sockets ready to read data
        for rsock in rl:
            if rsock is lsock:
                # A new connection has arrived
                nsock, cliaddr = lsock.accept()
                print("Received new connection from", cliaddr)
                
                # Add to state tracking if identity check passes
                if identity(nsock):
                    csocks.append(nsock)
                    client_states[nsock] = {"state": "menu"}  # Initialize client state
                    last_active[nsock] = time.time()
                    print(f"New client state initialized: {client_states[nsock]}")
                    nsock.send("Welcome! Please select an option:\n".encode('ascii'))  # Send menu prompt

                else:
                    print(f"Identity check failed for {cliaddr}. Closing connection.")
                    nsock.close()
            else:
                # Data is available to read on an existing connection
                try:
                    # Read the message from the client
                    message = rsock.recv(1000).decode('ascii').strip()
                    
                    if not message:  # Empty message indicates client disconnected
                        raise ConnectionResetError("Client disconnected.")
                    
                    # Process the message based on the client's state
                    process_client_message(rsock, message)

                except ConnectionResetError as e:
                    try:
                        print(f"Connection with {rsock.getpeername()} reset: {e}")
                    except OSError:
                        print("Connection reset: Unable to get peer name.")
                    clean_up_client(rsock)

                except OSError as e:
                    if e.errno == 107:  # Handle "Transport endpoint is not connected"
                        print(f"Socket error: {e}. Cleaning up client.")
                        clean_up_client(rsock)
                    else:
                        raise  # Re-raise other OSError exceptions

                except Exception as e:
                    print(f"Unexpected error with client: {e}")
                    clean_up_client(rsock)  # Clean up resources

        # timeout management section
        current_time = time.time()
        for rsock in list(csocks):
            if current_time - last_active.get(rsock, current_time) > timeout:
                print(f"Session timed out for {rsock.getpeername()}")
                clean_up_client(rsock)  # Use clean_up_client here
                del last_active[rsock]

        

    # Code should never reach here
    lsock.close()