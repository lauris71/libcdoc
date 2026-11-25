// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

package ee.ria.cdoc;

import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedInputStream;

public class IStreamSource extends DataSource {
    private InputStream ifs;

    public IStreamSource(InputStream ifs) {
        if (ifs.markSupported()) {
            this.ifs = ifs;
        } else {
            this.ifs = new BufferedInputStream(ifs, 100000000);
        }
        this.ifs.mark(100000000);
    }

    @Override
    public long seek(long pos) {
        System.err.format("IStreamSource: seek(%d)\n", pos);
        try {
            ifs.reset();
            long nskipped = 0;
            while (nskipped < pos) {
                nskipped += ifs.skip(pos - nskipped);
            }
        } catch (IOException exc) {
            System.err.format("IStreamSource: seek - exception: %s\n", exc.getMessage());
            return CDoc.INPUT_STREAM_ERROR;
        }
        return CDoc.OK;
    }
    
    public long read(byte[] dst) {
        System.err.format("IStreamSource: read([%d])\n", dst.length);
        try {
            int nread = 0;
            while (nread < dst.length) {
                int val = ifs.read(dst, nread, dst.length - nread);
                if (val < 0) return nread;
                nread += val;
            }
            return nread;
        } catch (IOException exc) {
            System.err.format("IStreamSource: read - exception: %s\n", exc.getMessage());
            return CDoc.INPUT_STREAM_ERROR;
        }
    }
    
    public boolean isError() {
        try {
            long avail = ifs.available();
        } catch (IOException exc) {
            return true;
        }
        return false;
    }
    
    public boolean isEof() {
        try {
            long avail = ifs.available();
            if (avail > 0) return false;
        } catch (IOException exc) {
            return true;
        }
        return true;
    }
}
