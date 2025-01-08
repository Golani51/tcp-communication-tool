import socket
import sys

def error(reason):
    print(f"Protocol Violation: {reason}")
    return

def display_menu():
    print("\n--- Menu ---")
    print("a. Practice computation of Network Number")
    print("b. Practice computation of Broadcast Address")
    print("c. Practice computation of Netmask in DDN (Dotted Decimal Notation)")
    print("d. Check if two addresses belong to the same network (TRUE or FALSE)")
    print("e. Check if an IP address is Private or Public")
    print("f. Exit")
    return input("Enter your choice: ")

# Create a TCP client socket
clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientsocket.settimeout(30)  # Set a timeout for socket operations

try:
    # Attempt to connect to the server
    try:
        clientsocket.connect((sys.argv[1], int(sys.argv[2])))
    except ConnectionRefusedError:
        print("Error: Unable to connect to the server. Ensure the server is running and accessible.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error during connection: {e}")
        sys.exit(1)

    # Phase 1: Identity
    while True:
        try:
            rmsg = clientsocket.recv(1000).decode("ascii")
            if not rmsg:
                print("Server disconnected.")
                sys.exit(1)
        except socket.timeout:
            print("Error: Server response timed out.")
            sys.exit(1)

        print("Rcvd:", rmsg)
        
        if rmsg != "IDENTITY:":
            error("IDENTITY")
         
        while True:
            smsg = input("Enter ID (cannot be blank): ").strip()
            if smsg:  # Ensure ID is not blank
                clientsocket.send(smsg.encode("ascii"))
                break
            else:
                print("Error: ID cannot be blank. Please enter a valid ID.")
        
        # Wait for confirmation or error from server
        try:
            rmsg = clientsocket.recv(1000).decode("ascii")
            if not rmsg:
                print("Server disconnected.")
                sys.exit(1)
        except socket.timeout:
            print("Error: Server response timed out.")
            sys.exit(1)
        
        print("Server:", rmsg)
        if "ERROR" not in rmsg:
            break  # Exit the identity loop if the server accepted the ID

    # Phase 2: Menu Interaction
    while True:
        choice = display_menu()
        if choice.lower() not in ["a", "b", "c", "d", "e", "f"]:
            print("Invalid choice. Please select a valid option.")
            continue
        
        clientsocket.send(choice.encode("ascii"))

        if choice == "f":
            print("Exiting...")
            try:
                while True:
                    rmsg = clientsocket.recv(1000).decode("ascii")
                    if not rmsg:
                        print("Server disconnected.")
                        break
                    print(rmsg)  # Print each line of the server's response
                    if "Thank you for participating!" in rmsg:
                        break  # Exit once the summary is fully displayed
            except socket.timeout:
                print("Error: Server response timed out.")
            break
        try:
            rmsg = clientsocket.recv(1000).decode("ascii")
            if not rmsg:
                print("Server disconnected.")
                sys.exit(1)
        except socket.timeout:
            print("Error: Server response timed out.")
            sys.exit(1)
        
        print(f"Server: {rmsg}")
        
        if "Compute" in rmsg or "Check" in rmsg:
            answer = input("Enter your answer (e.g., TRUE, FALSE, or a valid IP/Netmask): ").strip().upper()
            while not answer:  # Ensure non-empty input
                print("Answer cannot be blank. Please try again.")
                answer = input("Enter your answer (e.g., TRUE, FALSE, or a valid IP/Netmask): ").strip().upper()
            clientsocket.send(answer.encode("ascii"))
            try:
                rmsg = clientsocket.recv(1000).decode("ascii")
                if not rmsg:
                    print("Server disconnected.")
                    sys.exit(1)
            except socket.timeout:
                print("Error: Server response timed out.")
                sys.exit(1)
            
            print(f"Server: {rmsg}")
        elif "Session Summary" in rmsg:
            print("\n" + rmsg)
            break  # Exit after displaying the summary
        else:
            print(f"Unexpected server message: {rmsg}")

except KeyboardInterrupt:
    print("\nClient terminated by user.")
finally:
    clientsocket.close()