"""
Where solution code to HW5 should be written.  No other files should
be modified.
"""

import socket
import io
import time
import typing
import struct
import homework5
import homework5.logging

# Holds the expected sequence number to be received
EXPECTED_SEQUENCE = 0
# Holds the estimated round trip time in order to determine the timeout
ESTIMATED_RTT = 0
# Holds the SampleRTT for the last packet sent.  Initially 1.5
SAMPLE_RTT = 1.5
# Holds the Deviation of RTT
DEV_RTT = 0
# Holds the Timeout Value
TIMEOUT = 1
# Holds the current time in the computer
TIME_OF_TRANSMIT = 0
# Holds the data in case that there is a timeout in order to retransmit
OLD_DATA = bytes()

SUCCESS = True

def reset_timer():
    global TIME_OF_TRANSMIT
    TIME_OF_TRANSMIT = time.time()


def update_timeout() -> float:
    """
    Calculate the Timeout by updating the EstimatedRTT and the DevRTT

    :return:  Timeout Value
    """
    global TIME_OF_TRANSMIT, ESTIMATED_RTT, SAMPLE_RTT, TIMEOUT, DEV_RTT

    SAMPLE_RTT = time.time() - TIME_OF_TRANSMIT

    # If the sample RTT is Negative, then there was never a packet sent by this sender, thus
    #    assume the TIMEOUT is 1.5
    if TIME_OF_TRANSMIT == 0:
        TIMEOUT = 1
        return TIMEOUT

    ESTIMATED_RTT = .875 * ESTIMATED_RTT + (.125 * SAMPLE_RTT)

    DEV_RTT = (1 - .25) * DEV_RTT + (.25 * (SAMPLE_RTT - ESTIMATED_RTT))

    TIMEOUT = ESTIMATED_RTT + (4 * DEV_RTT)
    return TIMEOUT


def update_sequence ()-> int:
    """
    Will update the Global expected sequence, and with this, whenever it exceeds a
    value greater than 9999 then wrap around to zero (thus no sequences greater than 0)

    :return: New sequence numbers
    """
    global EXPECTED_SEQUENCE

    if EXPECTED_SEQUENCE > 9999:
        EXPECTED_SEQUENCE = 0
        return EXPECTED_SEQUENCE

    EXPECTED_SEQUENCE += 1

    return EXPECTED_SEQUENCE


def get_curr_seq() -> int:
    """

    :return:  Return the current EXPECTED_SEQUENCE
    """

    return EXPECTED_SEQUENCE


def make_packet(seq_num: int, data: bytearray = None) -> bytes:
    """
    Make a packet with header info like sequence number

    :param seq_num: The Sequence number that is expected or sent back
    :param data: The data that must be appended.  It is None by default when there is no Data
    :return: a byte array to be sent
    """
    packet = struct.pack("I", seq_num)

    if data is not None:
        packet += data

    return packet


def decode_packet(packet: bytes) -> list:
    """
    Take in a packet and remove the header.   Return the data

    :param packet: Packet to be decoded
    :return: A list that will contain the sequence number and then the actual message
    """
    seq_num = packet[:4]
    seq_num = struct.unpack("I", seq_num)
    seq_num = seq_num[0]

    if len(packet) > 4:
        data = packet[4:]
        return[seq_num, data]

    return [seq_num]


def send(sock: socket.socket, data: bytes):
    """
    Implementation of the sending logic for sending data over a slow,
    lossy, constrained network.

    Args:
        sock -- A socket object, constructed and initialized to communicate
                over a simulated lossy network.
        data -- A bytes object, containing the data to send over the network.
    """

    # determines if the last packet sent was successfully transmitted
    global SUCCESS, EXPECTED_SEQUENCE, TIMEOUT

    # Naive implementation where we chunk the data to be sent into
    # packets as large as the network will allow, and then send them
    # over the network, pausing half a second between sends to let the
    # network "rest" :)
    logger = homework5.logging.get_logger("hw5-sender")

    # Let chunk size be the length of the message minus the header
    # and some padding to fit the of the sequence numer
    chunk_size = homework5.MAX_PACKET - 4

    # let the pause value be determined by the timeout value
    pause = TIMEOUT

    offsets = range(0, len(data), chunk_size)
    for chunk in [data[i:i + chunk_size] for i in offsets]:
        # Assume a chunk transmission failed until the ack proves
        # it wrong
        SUCCESS = False

        reset_timer()
        # keep sending until the packet has been successfully acknowledged
        sock.send(make_packet(EXPECTED_SEQUENCE, chunk))

        # set teh timeout for a receive of an Ack
        sock.settimeout(TIMEOUT)

        while True:
            # Try to fetch the data from the acknowledgement packet
            try:
                # Fetch the acknowledge packet
                data = sock.recv(homework5.MAX_PACKET)
                sequence_num = decode_packet(data)[0]

                # If the acknowledgement packet corresponds as
                # Expected,  continue with the next
                if sequence_num is EXPECTED_SEQUENCE:
                    update_timeout()
                    update_sequence()
                    break

            # If the ack packet never arrived, resend the whole data packet
            except socket.timeout:
                sock.send(make_packet(EXPECTED_SEQUENCE, chunk))

        pause = TIMEOUT


def recv(sock: socket.socket, dest: io.BufferedIOBase) -> int:
    """
    Implementation of the receiving logic for receiving data over a slow,
    lossy, constrained network.

    Args:
        sock -- A socket object, constructed and initialized to communicate
                over a simulated lossy network.

    Return:
        The number of bytes written to the destination.
    """
    global EXPECTED_SEQUENCE

    logger = homework5.logging.get_logger("hw5-receiver")

    num_bytes = 0
    while True:
        try:
            data = sock.recv(homework5.MAX_PACKET)

            # Kill the process as soon as there is nothing else to send
            if not data:
                break

            # Gather the packet and retrieve the sequence number and data
            new_packet = decode_packet(data)
            header_only = new_packet[0]
            data_only = new_packet[1]

            # Check if the packet received is not off
            if header_only == EXPECTED_SEQUENCE:

                # If the packet received also contains data, then send an ack
                if data_only is not None:
                    # Send an Acknowledgement that the data received corresponds
                    # to expected value
                    sock.send(make_packet(EXPECTED_SEQUENCE))

                    logger.info("Received %d bytes", len(data_only))

                    dest.write(data_only)
                    num_bytes += len(data_only)
                    dest.flush()

                    # Update the expected sequence if the data that we received
                    # is the one that was expected
                    update_sequence()

            # If the packet sequence is off, resent the
            else:
                sock.send(make_packet(EXPECTED_SEQUENCE))

        # If there was a timeout, continue
        except socket.timeout:
            continue

    return num_bytes
