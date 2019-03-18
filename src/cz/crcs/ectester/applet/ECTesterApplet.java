/*
 * ECTester, tool for testing Elliptic curve cryptography implementations.
 * Copyright (c) 2016-2019 Petr Svenda <petr@svenda.com>
 * Copyright (c) 2016-2019 Jan Jancar  <johny@neuromancer.sk>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/*
 * PACKAGEID: 4543546573746572
 * APPLETID: 454354657374657230333362 // VERSION v0.3.3
 */
package cz.crcs.ectester.applet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * Applet part of ECTester, a tool for testing Elliptic curve support on javacards.
 *
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ECTesterApplet extends AppletBase {
    protected ECTesterApplet(byte[] buffer, short offset, byte length) {
        super(buffer, offset, length);
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        // applet instance creation
        new ECTesterApplet(bArray, bOffset, bLength);
    }

    short getOffsetCdata(APDU apdu) {
        return ISO7816.OFFSET_CDATA;
    }

    short getIncomingLength(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        return (short) (0xff & apduBuffer[ISO7816.OFFSET_LC]);
    }

    short getBase() {
        return AppletBase.BASE_221;
    }
}
