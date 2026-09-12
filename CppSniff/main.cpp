#include <iostream>
#include <pcap.h>
#include <string>
#include <iomanip>
#include <fstream>
#include <thread>
#include <chrono>

//Log output to console and logfile
void log_output (std::ofstream& file, const std::string& text) {
    std::cout << text;
    file << text;
}

//Packet handler takes packet metadata and date then logs it to console and text file
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    std::ofstream* logfile = reinterpret_cast<std::ofstream*>(user_data);
    std::string line = "\n=================== PACKET CAPTURED ===================\n";
    line += "Packet Length: " + std::to_string(pkthdr->len) + " bytes\n";
    log_output (*logfile, line);

    //Loop through all captured bites to log
    for (bpf_u_int32 i = 0; i < pkthdr->caplen; i += 16) {
        std::stringstream ss;

        //Create a visual anchor for human readability
        ss << std::hex << std::setw(4) << std::setfill('0') << i << "  ";

        log_output(*logfile, ss.str());

        //Store packet data to static string for output later
        for (bpf_u_int32 j = 0; j < 16; j++) {
            if (i + j < pkthdr->caplen) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(packet[i + j]) << " ";
            } else {
                ss << "   ";
            }
        }
        ss << " | ";

        for (bpf_u_int32 j = 0; j < 16; j++) {
            if (i + j < pkthdr->caplen) {
                u_char byte = packet[i + j];
                if (byte >= 32 && byte <= 126) {
                    ss << static_cast<char>(byte);
                } else {
                    ss << '.';
                }
            } else {
                ss << ' ';
            }
        }


        ss << "\n";
        log_output(*logfile, ss.str());



    }

    log_output(*logfile, "=======================================================\n\n");
    logfile->flush(); // Ensure data writes to disk immediately

}

int main() {

    std::ofstream logfile("packet_log.txt", std::ios::out | std::ios::app);
    if (!logfile.is_open()) {
        std::cerr << "Failed to open packet_log.txt for writing!" << std::endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    std::string dev_input;
    std::cout << "Enter interface name (e.g., eth0, wlan0): ";
    std::cin >> dev_input;
    const char* dev = dev_input.c_str();


    //Create pointer for network interface
    pcap_t* handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);

    //Check if pointer errors out and handle said error
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Successfully opened device for capturing!" << std::endl;

    //Create BFP filter to ensure I dont capture roomates traffic cus that'd be wierd

    std::string ip_input;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cout << "Enter BPF filter expression (e.g., 'host 10.0.2.15'): ";
    std::cin >> ip_input;
    std::string filter_exp = "host " + ip_input;
    bpf_program fp;

    while (true) {
        //Handle error if filter cant be parsed
        if (pcap_compile(handle, &fp, filter_exp.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            return 1;
        }

        //If filter fails to set handle error
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            return 1;
        }

        std::cout << "Filter set to: '" << filter_exp << "'. Starting capture loop..." << std::endl;
        std::cout << "Sniffer started! Logging traffic to console and 'packet_log.txt'...\n";

        //Starts pcap loop to run packet_handler function infinitely
        int result = pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&logfile));
        pcap_freecode(&fp);
        pcap_close(handle);

        if (result == -1) {
            std::cerr << "\n[!] Network interface lost or error occurred: " << pcap_geterr(handle) << "\n";
        }
        std::cerr << "[!] Attempting to reconnect in 3 seconds...\n";
        std::this_thread::sleep_for(std::chrono::seconds(3));


    }

    logfile.close();
    return 0;

}
