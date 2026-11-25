// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef __WRAPPER_H__
#define __WRAPPER_H__

#include <vector>

namespace libcdoc {

struct DataBuffer {
    std::vector<uint8_t> *data;

    DataBuffer() : data(&vec) {}
    DataBuffer(std::vector<uint8_t> *_data) : data(_data) {}

    const std::vector<uint8_t>& getData() { return *data; }
    void setData(const std::vector<uint8_t>& _data) { *data = _data; }

    void reset() { data = &vec; }
private:
    std::vector<uint8_t> vec;
};

struct CertificateList {
    std::vector<std::vector<uint8_t>> *data;

    CertificateList() : data(&vec) {}
    CertificateList(std::vector<std::vector<uint8_t>> *_data) : data(_data) {}

    const std::vector<std::vector<uint8_t>>& getData() { return *data; }
    void setData(const std::vector<std::vector<uint8_t>>& _data) { *data = _data; }

    void clear() { data->clear(); }
    size_t size() { return data->size(); }
    void addCertificate(const std::vector<uint8_t>& cert) { data->push_back(cert); }
    const std::vector<uint8_t>& getCertificate(unsigned int idx) { return data->at(idx); }

    void reset() { data = &vec; }
private:
    std::vector<std::vector<uint8_t>> vec;
};

}

#endif
