// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

package ee.ria.cdoc;

public class CDocException extends java.lang.Exception {
    public final int code;
    CDocException(int code, String msg) {
        super(msg);
        this.code = code;
    }
}
