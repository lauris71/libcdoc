// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef TOOLCONF_H
#define TOOLCONF_H

#include "Configuration.h"

#include "Utils.h"

#include <sstream>

namespace libcdoc {

/**
 * @brief The class implements libcdoc::Configuration and holds configuration for cdoc_tool.
 */
struct ToolConf : public JSONConfiguration {
    struct ServerData {
        std::string ID;
        // Either capsule server url or comma-separated list of share servers
        std::string url;
    };

    ToolConf() : JSONConfiguration() {};
    ToolConf(std::istream& ifs) : JSONConfiguration(ifs) {}

    /**
     * @brief Version of CDOC container to be created, either 1 or 2.
     */
    int cdocVersion = 2;

    /**
     * @brief If a Smart-card handling library has to be loaded or not.
     */
    bool libraryRequired = false;

    /**
     * @brief Full path to the Smart-card handling library to be used.
     */
    std::string library;

    std::vector<ServerData> servers;

    /**
     * @brief Files to be encrypted, or file to be decrypted.
     */
    std::vector<std::string> input_files;

    /**
     * @brief The name of CDOC container file to be created, or path where to decrypt the files from CDOC container.
     */
    std::string out;

    /**
     * @brief If the label has to be generated.
     */
    bool gen_label = false;

    /**
     * @brief The list of accepted keyserver certificates (empty - accept all)
     */
    std::vector<std::vector<uint8_t>> accept_certs;

    std::string getValue(std::string_view domain, std::string_view param) const final {
        for (auto& sdata : servers) {
            if (sdata.ID == domain) {
                if (param == Configuration::KEYSERVER_SEND_URL) {
                    return sdata.url;
                } else if (param == Configuration::KEYSERVER_FETCH_URL) {
                    return sdata.url;
#ifdef HAS_KEYSHARES
                } else if (param == Configuration::SHARE_SERVER_URLS) {
                    // Return JSON
                    std::stringstream ss;
                    auto list = libcdoc::split(sdata.url, ',');
                    ss << "[";
                    for (unsigned int i = 0; i < list.size(); i++) {
                        if (i > 0) ss << ",";
                        ss << '"';
                        ss << list[i];
                        ss << '"';
                    }
                    ss << "]";
                    return ss.str();
#endif
                }
            }
        }
        return JSONConfiguration::getValue(domain, param);
    }
};


}


#endif // TOOLCONF_H
