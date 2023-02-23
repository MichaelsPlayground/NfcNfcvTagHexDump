package de.androidcrypto.nfcnfcvtaghexdump;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.NfcA;
import android.nfc.tech.NfcV;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.provider.Settings;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    TextView dumpField, readResult;
    private NfcAdapter mNfcAdapter;
    String dumpExportString = "";
    byte[] dumpExportByte = new byte[0];
    String tagIdString = "";
    String tagTypeString = "";
    private static final int REQUEST_PERMISSION_WRITE_EXTERNAL_STORAGE = 100;
    Context contextSave;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);
        contextSave = getApplicationContext();

        dumpField = findViewById(R.id.tvMainDump1);
        readResult = findViewById(R.id.tvMainReadResult);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {
        // Read and or write to Tag here to the appropriate Tag Technology type class
        // in this example the card should be an Ndef Technology Type

        System.out.println("NFC tag discovered");
        writeToUiAppend(readResult, "NFC tag discovered");

        String[] techList = tag.getTechList();
        for (int i = 0; i < techList.length; i++) {
            writeToUiAppend(readResult, "TechList: " + techList[i]);
            System.out.println("TechList: " + techList[i]);
        }
        byte[] tagId = tag.getId();
        tagIdString = bytesToHex(tag.getId());
        writeToUiAppend(readResult, "TagId: " + tagIdString);
        System.out.println("TagId: " + tagIdString);

        NfcV nfcV = null;

        nfcV = NfcV.get(tag);

        if (nfcV != null) {

            writeToUiAppend(readResult, "nfcV not null");


            runOnUiThread(() -> {
                Toast.makeText(getApplicationContext(),
                        "NFC tag is NfcV compatible",
                        Toast.LENGTH_SHORT).show();
            });

            // Make a Sound
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
            } else {
                Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
                v.vibrate(200);
            }

            // tranceive length
            int maxTranceiveLength = nfcV.getMaxTransceiveLength();
            writeToUiAppend(readResult, "maxTranceiveLength: " + maxTranceiveLength + " bytes");

            byte responseFlags = nfcV.getResponseFlags();
            writeToUiAppend(readResult, "responseFlags: " + responseFlags);
            System.out.println("responseFlags: " + responseFlags);

            byte dsfId = nfcV.getDsfId();
            writeToUiAppend(readResult, "dsfId: " + dsfId);
            System.out.println("dsfId: " + dsfId);

            // connect to the tag
            try {
                nfcV.connect();
                writeToUiAppend(readResult, "connected to the tag");

                // inventory
                byte[] UIDFrame = new byte[] { (byte) 0x26, (byte) 0x01, (byte) 0x00 };
                byte[] responseInventory = nfcV.transceive(UIDFrame);
                String responseInventoryString = bytesToHex(responseInventory);
                writeToUiAppend(readResult, "responseInventory: " + responseInventoryString);
                System.out.println("responseInventory: " + responseInventoryString);


                byte[] GetSystemInfoFrame1bytesAddress = new byte[] { (byte) 0x02, (byte) 0x2B };
                byte[] responseGetSystemInfoFrame1bytesAddress = nfcV.transceive(GetSystemInfoFrame1bytesAddress);
                String responseGetSystemInfoFrame1bytesAddressString = bytesToHex(responseGetSystemInfoFrame1bytesAddress);
                writeToUiAppend(readResult, "responseGetSystemInfoFrame1bytesAddress: " + responseGetSystemInfoFrame1bytesAddressString);
                System.out.println("responseGetSystemInfoFrame1bytesAddress: " + responseGetSystemInfoFrame1bytesAddressString);


                // try to read
                int offset = 0;  // offset of first block to read
                //int blocks = 1;  // number of blocks to read
                int blocks = 4;  // number of blocks to read = 52 blocks with 4 bytes each = 208 bytes


                byte[] cmd = new byte[]{
                        (byte)0x60,                  // flags: addressed (= UID field present)
                        (byte)0x23,                  // command: READ MULTIPLE BLOCKS
                        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,  // placeholder for tag UID
                        (byte)(offset & 0x0ff),      // first block number
                        (byte)((blocks - 1) & 0x0ff) // number of blocks (-1 as 0x00 means one block)
                };
                System.arraycopy(tagId, 0, cmd, 2, 8);
                byte[] response = nfcV.transceive(cmd);
                String responseString = bytesToHex(response);
                writeToUiAppend(readResult, "response length: " + response.length);
                System.out.println("response length: " + response.length);
                writeToUiAppend(readResult, "response: " + responseString);
                System.out.println("response: " + responseString);

                // trim the first 2 bytes from response
                byte[] responseTrimFirst = trimFirst2Bytes(response);
                writeToUiAppend(readResult, "responseTrimFirst length: " + responseTrimFirst.length);
                System.out.println("responseTrimFirst length: " + responseTrimFirst.length);
                System.out.println("responseTrimFirst: " + bytesToHex(responseTrimFirst));
                byte[] responseTrimLast = trimLastByte(responseTrimFirst);
                writeToUiAppend(readResult, "responseTrimLast length: " + responseTrimLast.length);
                System.out.println("responseTrimLast length: " + responseTrimLast.length);
                System.out.println("responseTrimLast: " + bytesToHex(responseTrimLast));

                //String dumpContent = dumpContentHeader + "\n\nUser memory content:\n" + HexDumpOwn.prettyPrint(ntagMemory, 16);
                String dumpContent = HexDumpOwn.prettyPrint(responseTrimFirst, 16);
                writeToUiAppend(readResult, dumpContent);
                // note: response contains at ther beginning 2 00x bytes (remove) und at the end 2 00x bytes (remove)

                // read the tags 52 blocks separately
                int NUMBER_OF_BLOCKS = 52;
                int NUMBER_OF_BYTES_IN_BLOCK = 4;
                byte[] responseComplete = new byte[(NUMBER_OF_BLOCKS * NUMBER_OF_BYTES_IN_BLOCK)];
                for (int i = 0; i < NUMBER_OF_BLOCKS; i++) {
                    byte[] responseBlock = readOneBlock(nfcV, tagId, i);
                    if (responseBlock != null) {
                        // copy the new bytes to responseComplete
                        System.arraycopy(responseBlock, 0, responseComplete, (i * NUMBER_OF_BYTES_IN_BLOCK), NUMBER_OF_BYTES_IN_BLOCK);
                        writeToUiAppend(readResult, "processing block: " + i);
                        //String dumpBlock = HexDumpOwn.prettyPrint(responseBlock, 16);
                        //writeToUiAppend(readResult, dumpBlock);
                    } else {
                        writeToUiAppend(readResult, "error on reading block " + i);
                    }
                }
                writeToUiAppend(readResult, "complete content");
                String dumpComplete = HexDumpOwn.prettyPrint(responseComplete, 16);
                writeToUiAppend(readResult, dumpComplete);
                System.out.println("dumpComplete: " + dumpComplete);

                // for exporting
                //tagIdString = bytesToHex(tagId);
                dumpExportString = dumpComplete;
                dumpExportByte = responseComplete.clone();

            } catch (IOException e) {
                writeToUiAppend(readResult, "Error: " + e.getMessage());
                throw new RuntimeException(e);
            }


        } else {
            writeToUiAppend(readResult, "nfcV == null");
        }

        /** timestamps
         * GMT	Fri Feb 03 2023 23:00:00 GMT+0000
         * 	1675465200
         * GMT  Sat Feb 11 2023 22:59:59 GMT+0000
         *  1676156399
         */

        // actual timestamp
        // https://stackoverflow.com/a/29273645/8166854
        int unixTime = (int)(System.currentTimeMillis() / 1000);
        // NOTE: big endian order
        byte[] productionDate = new byte[]{
                (byte) (unixTime >> 24),
                (byte) (unixTime >> 16),
                (byte) (unixTime >> 8),
                (byte) unixTime
        };
        System.out.println("UNIX time milliseconds: " + unixTime);
        System.out.println("UNIX time 4 bytes big endian: " + bytesToHex(productionDate));
        // actual
        // UNIX time milliseconds: 1677149817
        // UNIX time 4 bytes big endian: 63f74679

        System.out.println("== dateFeb042023 ==");
        Date dateFeb232023 = getDate(2023, 02, 23, 11,50,01);
        byte[] dateFeb232023Ts = getUnixTimestampBigEndian(dateFeb232023.getTime() / 1000);
        System.out.println("dateFeb232023: " + dateFeb232023 + " TS: " + bytesToHex(dateFeb232023Ts));

        System.out.println("BIG ENDIAN");
        //byte[] dateFeb232023TsV = longToBytes(dateFeb232023.getTime() / 1000);
        byte[] dateFeb232023TsV = longToByteArrayBigEndian(dateFeb232023.getTime() / 1000);
        System.out.println("dateFeb232023: " + dateFeb232023 + " TS: " + bytesToHex(dateFeb232023TsV));
        //long dateFeb232023TsVL = bytesToLong(dateFeb232023TsV);
        long dateFeb232023TsVL = byteArrayToLongBigEndian(dateFeb232023TsV);
        Date dateFeb232023V = new Date(dateFeb232023TsVL * 1000);
        System.out.println("dateFeb232023V: " + dateFeb232023V + " TS: " + bytesToHex(dateFeb232023TsV));

        System.out.println("LITTLE ENDIAN");
        // little endian
        byte[] dateFeb232023TsVLE = longToByteArrayLittleEndian(dateFeb232023.getTime() / 1000);
        System.out.println("dateFeb232023: " + dateFeb232023 + " TS: " + bytesToHex(dateFeb232023TsVLE));
        //long dateFeb232023TsVL = bytesToLong(dateFeb232023TsV);

        long dateFeb232023TsVLLE = byteArrayToLongLittleEndian(dateFeb232023TsVLE);
        Date dateFeb232023VLE = new Date(dateFeb232023TsVLLE * 1000);
        System.out.println("dateFeb232023VLE: " + dateFeb232023VLE + " TS: " + bytesToHex(dateFeb232023TsVLE));

        System.out.println("== dateFeb042023 ==");
        Date dateFeb042023 = getDate(2023, 02, 04, 00,00,00);
        byte[] dateFeb042023Ts = getUnixTimestampBigEndian(dateFeb042023.getTime() / 1000);
        System.out.println("dateFeb042023: " + dateFeb042023 + " TS: " + bytesToHex(dateFeb042023Ts));

        Date dateFeb112023 = getDate(2023, 02, 11, 23,59,59);
        byte[] dateFeb112023Ts = getUnixTimestampBigEndian(dateFeb112023.getTime() / 1000);
        System.out.println("dateFeb112023: " + dateFeb112023 + " TS: " + bytesToHex(dateFeb112023Ts));


        /*
        NfcA nfcA = null;

        try {
            nfcA = NfcA.get(tag);

            if (nfcA != null) {
                runOnUiThread(() -> {
                    Toast.makeText(getApplicationContext(),
                            "NFC tag is Nfca compatible",
                            Toast.LENGTH_SHORT).show();
                });

                // Make a Sound
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
                } else {
                    Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
                    v.vibrate(200);
                }

                nfcA.connect();
                dumpExportString = "";
                runOnUiThread(() -> {
                    readResult.setText("");
                });


                // check that the tag is a NTAG213/215/216 manufactured by NXP - stop if not
                String ntagVersion = NfcIdentifyNtag.checkNtagType(nfcA, tag.getId());
                if (ntagVersion.equals("0")) {
                    runOnUiThread(() -> {
                        readResult.setText("NFC tag is NOT of type NXP NTAG213/215/216");
                        Toast.makeText(getApplicationContext(),
                                "NFC tag is NOT of type NXP NTAG213/215/216",
                                Toast.LENGTH_SHORT).show();
                    });
                    return;
                }

                int nfcaMaxTranceiveLength = nfcA.getMaxTransceiveLength(); // important for the readFast command
                int ntagPages = NfcIdentifyNtag.getIdentifiedNtagPages();
                int ntagMemoryBytes = NfcIdentifyNtag.getIdentifiedNtagMemoryBytes();
                tagIdString = getDec(tag.getId());
                tagTypeString = NfcIdentifyNtag.getIdentifiedNtagType();
                String nfcaContent = "raw data of " + tagTypeString + "\n" +
                        "number of pages: " + ntagPages +
                        " total memory: " + ntagMemoryBytes +
                        " bytes\n" +
                        "tag ID: " + bytesToHex(NfcIdentifyNtag.getIdentifiedNtagId()) + "\n" +
                        "tag ID: " + tagIdString + "\n";
                nfcaContent = nfcaContent + "maxTranceiveLength: " + nfcaMaxTranceiveLength + " bytes\n";
                // read the complete memory depending on ntag type
                byte[] headerMemory = new byte[16]; // 4 pages of each 4 bytes, e.g. manufacturer data
                byte[] ntagMemory = new byte[ntagMemoryBytes]; // user memory, 888 byte for a NTAG216
                byte[] footerMemory = new byte[20]; // 5 pages, e.g. dyn. lock bytes, configuration pages, password & pack

                // read the content of the tag in several runs

                // first we are reading the header
                System.out.println("reading the header");
                headerMemory = getFastTagDataRange(nfcA, 0, 3);
                if (headerMemory == null) {
                    writeToUiAppend(readResult, "ERROR on reading header, aborted");
                }
                String dumpContentHeader = "Header content:\n" + HexDumpOwn.prettyPrint(headerMemory);

                int footerStart = 4 + ntagPages;
                int footerEnd = 4 + footerStart;
                System.out.println("reading the footer");
                footerMemory = getFastTagDataRange(nfcA, footerStart, footerEnd);
                if (footerMemory == null) {
                    writeToUiAppend(readResult, "ERROR on reading footer, aborted");
                }
                // offset = footerStart * 4 = footerStart pages of 4 bytes each
                String dumpContentFooter = "Footer content:\n" + HexDumpOwn.prettyPrint(footerMemory, footerStart * 4);

                byte[] response;
                try {
                    //int nfcaMaxTranceiveLength = nfcA.getMaxTransceiveLength(); // my device: 253 bytes
                    int nfcaMaxTranceive4ByteTrunc = nfcaMaxTranceiveLength / 4; // 63
                    int nfcaMaxTranceive4ByteLength = nfcaMaxTranceive4ByteTrunc * 4; // 252 bytes
                    int nfcaNrOfFullReadings = ntagMemoryBytes / nfcaMaxTranceive4ByteLength; // 888 bytes / 252 bytes = 3 full readings
                    int nfcaTotalFullReadingBytes = nfcaNrOfFullReadings * nfcaMaxTranceive4ByteLength; // 3 * 252 = 756
                    int nfcaMaxTranceiveModuloLength = ntagMemoryBytes - nfcaTotalFullReadingBytes; // 888 bytes - 756 bytes = 132 bytes
                    nfcaContent = nfcaContent + "nfcaMaxTranceive4ByteTrunc: " + nfcaMaxTranceive4ByteTrunc + "\n";
                    nfcaContent = nfcaContent + "nfcaMaxTranceive4ByteLength: " + nfcaMaxTranceive4ByteLength + "\n";
                    nfcaContent = nfcaContent + "nfcaNrOfFullReadings: " + nfcaNrOfFullReadings + "\n";
                    nfcaContent = nfcaContent + "nfcaTotalFullReadingBytes: " + nfcaTotalFullReadingBytes + "\n";
                    nfcaContent = nfcaContent + "nfcaMaxTranceiveModuloLength: " + nfcaMaxTranceiveModuloLength + "\n";

                    for (int i = 0; i < nfcaNrOfFullReadings; i++) {
                        System.out.println("starting round: " + i);
                        response = getFastTagDataRange(nfcA, (4 + (nfcaMaxTranceive4ByteTrunc * i)), (4 + (nfcaMaxTranceive4ByteTrunc * (i + 1)) - 1));
                        if (response == null) {
                            writeToUiAppend(readResult, "ERROR on reading user memory, aborted");
                        } else {
                            // success: response contains ACK or actual data
                            System.arraycopy(response, 0, ntagMemory, (nfcaMaxTranceive4ByteLength * i), nfcaMaxTranceive4ByteLength);
                        }
                    } // for

                    // now we read the nfcaMaxTranceiveModuloLength bytes, for a NTAG216 = 132 bytes
                    response = getFastTagDataRange(nfcA, (4 + (nfcaMaxTranceive4ByteTrunc * nfcaNrOfFullReadings)), (4 + (nfcaMaxTranceive4ByteTrunc * nfcaNrOfFullReadings) + (nfcaMaxTranceiveModuloLength / 4)));
                    if (response == null) {
                        writeToUiAppend(readResult, "ERROR on reading user memory, aborted");
                    } else {
                        // success: response contains ACK or actual data
                        System.arraycopy(response, 0, ntagMemory, (nfcaMaxTranceive4ByteLength * nfcaNrOfFullReadings), nfcaMaxTranceiveModuloLength);
                    }
                    nfcaContent = nfcaContent + "fast reading complete: " + "\n" + bytesToHex(ntagMemory) + "\n";

                    String finalNfcaRawText = nfcaContent;
                    // offset = 16 = 4 pages of 4 bytes each
                    String dumpContent = dumpContentHeader + "\n\nUser memory content:\n" + HexDumpOwn.prettyPrint(ntagMemory, 16);
                    dumpContent = dumpContent + "\n\n" + dumpContentFooter;
                    System.out.println(dumpContent);
                    dumpExportString = dumpContent;
                    String finalDumpContent = dumpContent;
                    runOnUiThread(() -> {
                        dumpField.setText(finalDumpContent);
                        readResult.setText(finalNfcaRawText);
                        System.out.println(finalNfcaRawText);
                    });

                } finally {
                    try {
                        nfcA.close();
                    } catch (IOException e) {
                        writeToUiAppend(readResult, "ERROR IOException: " + e);
                    }
                }
            }
        } catch (IOException e) {
            writeToUiAppend(readResult, "ERROR IOException: " + e);
            e.printStackTrace();
        }
        */
    }

    // gives 8 bytes for a long
    static byte[] longToByteArrayBigEndian(long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
    }

    static long byteArrayToLongBigEndian(byte[] array) {
        return ByteBuffer.wrap(array).getLong();
    }

    static byte[] longToByteArrayLittleEndian(long value) {
        return ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array();
        //return ByteBuffer.allocate(8).putLong(value).array();
    }

    static long byteArrayToLongLittleEndian(byte[] array) {
        return ByteBuffer.wrap(array).order(ByteOrder.LITTLE_ENDIAN).getLong();
        //return ByteBuffer.wrap(array).getLong();
    }


    // return ByteBuffer.wrap(array).order(ByteOrder.LITTLE_ENDIAN).getLong();


    // gives 8 bytes for a long
    public byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    public long bytesToLong(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(bytes);
        buffer.flip();//need flip
        return buffer.getLong();
    }

    private byte[] getUnixTimestampBigEndian(long unixTime) {
        return new byte[]{
                (byte) (unixTime >> 24),
                (byte) (unixTime >> 16),
                (byte) (unixTime >> 8),
                (byte) unixTime
        };
    }

    private Date getDate(int year, int month, int day, int hour, int minute, int second) {
        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.YEAR, year);
        cal.set(Calendar.MONTH, month);
        cal.set(Calendar.DAY_OF_MONTH, day);
        cal.set(Calendar.HOUR_OF_DAY, hour);
        cal.set(Calendar.MINUTE, minute);
        cal.set(Calendar.SECOND, second);
        cal.set(Calendar.MILLISECOND, 0);
        return cal.getTime();
    }

    private byte[] readOneBlock(NfcV nfcV, byte[] tagId, int blockNumber) {
        // try to read
        int offset = 0;  // offset of first block to read
        int blocks = 1;  // number of blocks to read
        //int blocks = 4;  // number of blocks to read = 52 blocks with 4 bytes each = 208 bytes
        byte[] RESPONSE_OK = new byte[]{
                (byte) 0x00, (byte) 0x00
        };

        byte[] cmd = new byte[]{
                (byte)0x60,                  // flags: addressed (= UID field present)
                (byte)0x23,                  // command: READ MULTIPLE BLOCKS
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,  // placeholder for tag UID
                //(byte)(offset & 0x0ff),      // first block number
                (byte)(blockNumber & 0x0ff),      // first block number
                (byte)((blocks - 1) & 0x0ff) // number of blocks (-1 as 0x00 means one block)
        };
        System.arraycopy(tagId, 0, cmd, 2, 8);
        try {
            byte[] response = nfcV.transceive(cmd);
            //System.out.println("blockNumber: " + blockNumber);
            //System.out.println("cmd: " + bytesToHex(cmd));
            //System.out.println("response: " + bytesToHex(response));
            byte[] responseByte = getResponseBytes(response);
            if (Arrays.equals(responseByte, RESPONSE_OK)) {
                return trimFirst2Bytes(response);
            } else {
                return null;
            }
        } catch (IOException e) {
            //throw new RuntimeException(e);
            return null;
        }
    }

    private byte[] getResponseByte(byte[] input) {
        return Arrays.copyOfRange(input, 0, 1);
    }

    private byte[] getResponseBytes(byte[] input) {
        return Arrays.copyOfRange(input, 0, 2);
    }

    private byte[] trimFirstByte(byte[] input) {
        return Arrays.copyOfRange(input, 1, (input.length));
    }
    private byte[] trimFirst2Bytes(byte[] input) {
        return Arrays.copyOfRange(input, 2, (input.length));
    }

    private byte[] trimLastByte(byte[] input) {
        return Arrays.copyOfRange(input, 0, (input.length - 1));
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    private String getDec(byte[] bytes) {
        long result = 0;
        long factor = 1;
        for (int i = 0; i < bytes.length; ++i) {
            long value = bytes[i] & 0xffl;
            result += value * factor;
            factor *= 256l;
        }
        return result + "";
    }

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
            String newString = message + "\n" + textView.getText().toString();
            textView.setText(newString);
        });
    }

    private void writeToUiToast(String message) {
        runOnUiThread(() -> {
            Toast.makeText(getApplicationContext(),
                    message,
                    Toast.LENGTH_SHORT).show();
        });
    }

    private byte[] getFastTagDataRange(NfcA nfcA, int fromPage, int toPage) {
        byte[] response;
        byte[] command = new byte[]{
                (byte) 0x3A,  // FAST_READ
                (byte) (fromPage & 0x0ff),
                (byte) (toPage & 0x0ff),
        };
        try {
            response = nfcA.transceive(command); // response should be 16 bytes = 4 pages
            if (response == null) {
                // either communication to the tag was lost or a NACK was received
                writeToUiAppend(readResult, "ERROR on reading page");
                return null;
            } else if ((response.length == 1) && ((response[0] & 0x00A) != 0x00A)) {
                // NACK response according to Digital Protocol/T2TOP
                writeToUiAppend(readResult, "ERROR NACK received");
                // Log and return
                return null;
            } else {
                // success: response contains ACK or actual data
            }
        } catch (TagLostException e) {
            // Log and return
            writeToUiAppend(readResult, "ERROR Tag lost exception");
            return null;
        } catch (IOException e) {
            writeToUiAppend(readResult, "ERROR IOException: " + e);
            e.printStackTrace();
            return null;
        }
        return response;
    }

    private void showWirelessSettings() {
        Toast.makeText(this, "You need to enable NFC", Toast.LENGTH_SHORT).show();
        Intent intent = new Intent(Settings.ACTION_WIRELESS_SETTINGS);
        startActivity(intent);
    }

    private void exportDumpMail() {
        if (dumpExportString.isEmpty()) {
            writeToUiToast("Scan a tag first before sending emails :-)");
            return;
        }
        String subject = "Dump NFC-Tag " + tagTypeString + " UID: " + tagIdString;
        String body = dumpExportString;
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_SUBJECT, subject);
        intent.putExtra(Intent.EXTRA_TEXT, body);
        if (intent.resolveActivity(getPackageManager()) != null) {
            startActivity(intent);
        }
    }

    private void exportDumpFile() {
        if (dumpExportString.isEmpty()) {
            writeToUiToast("Scan a tag first before writing files :-)");
            return;
        }
        //verifyPermissionsWriteString();
        writeStringToExternalSharedStorage();
    }

    private void exportBinaryDumpFile() {
        if (dumpExportByte.length == 0) {
            writeToUiToast("Scan a tag first before writing files :-)");
            return;
        }
        //verifyPermissionsWriteString();
        writeByteToExternalSharedStorage();
    }

    // section external storage permission check
    private void verifyPermissionsWriteString() {
        String[] permissions = {Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE};
        if (ContextCompat.checkSelfPermission(this.getApplicationContext(),
                permissions[0]) == PackageManager.PERMISSION_GRANTED
                && ContextCompat.checkSelfPermission(this.getApplicationContext(),
                permissions[1]) == PackageManager.PERMISSION_GRANTED) {
            writeStringToExternalSharedStorage();
        } else {
            ActivityCompat.requestPermissions(this,
                    permissions,
                    REQUEST_PERMISSION_WRITE_EXTERNAL_STORAGE);
        }
    }

    private void writeStringToExternalSharedStorage() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        // Optionally, specify a URI for the file that should appear in the
        // system file picker when it loads.
        //boolean pickerInitialUri = false;
        //intent.putExtra(DocumentsContract.EXTRA_INITIAL_URI, pickerInitialUri);
        // get filename from edittext
        String filename = tagIdString + ".txt";
        // sanity check
        if (filename.equals("")) {
            writeToUiToast("scan a tag before writing the content to a file :-)");
            return;
        }
        intent.putExtra(Intent.EXTRA_TITLE, filename);
        fileSaverActivityResultLauncher.launch(intent);
    }

    ActivityResultLauncher<Intent> fileSaverActivityResultLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            new ActivityResultCallback<ActivityResult>() {
                @Override
                public void onActivityResult(ActivityResult result) {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        // There are no request codes
                        Intent resultData = result.getData();
                        // The result data contains a URI for the document or directory that
                        // the user selected.
                        Uri uri = null;
                        if (resultData != null) {
                            uri = resultData.getData();
                            // Perform operations on the document using its URI.
                            try {
                                // get file content from edittext
                                String fileContent = dumpExportString;
                                writeTextToUri(uri, fileContent);
                                String message = "file written to external shared storage: " + uri.toString();
                                writeToUiToast("file written to external shared storage: " + uri.toString());
                            } catch (IOException e) {
                                e.printStackTrace();
                                writeToUiToast("ERROR: " + e.toString());
                                return;
                            }
                        }
                    }
                }
            });

    private void writeTextToUri(Uri uri, String data) throws IOException {
        try {
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(contextSave.getContentResolver().openOutputStream(uri));
            outputStreamWriter.write(data);
            outputStreamWriter.close();
        } catch (IOException e) {
            System.out.println("Exception File write failed: " + e.toString());
        }
    }

    private void writeByteToExternalSharedStorage() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        // Optionally, specify a URI for the file that should appear in the
        // system file picker when it loads.
        //boolean pickerInitialUri = false;
        //intent.putExtra(DocumentsContract.EXTRA_INITIAL_URI, pickerInitialUri);
        // get filename from edittext
        String filename = tagIdString + ".dat";
        // sanity check
        if (filename.equals("")) {
            writeToUiToast("scan a tag before writing the content to a file :-)");
            return;
        }
        intent.putExtra(Intent.EXTRA_TITLE, filename);
        binaryFileSaverActivityResultLauncher.launch(intent);
    }

    ActivityResultLauncher<Intent> binaryFileSaverActivityResultLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            new ActivityResultCallback<ActivityResult>() {
                @Override
                public void onActivityResult(ActivityResult result) {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        // There are no request codes
                        Intent resultData = result.getData();
                        // The result data contains a URI for the document or directory that
                        // the user selected.
                        Uri uri = null;
                        if (resultData != null) {
                            uri = resultData.getData();
                            // Perform operations on the document using its URI.
                            try {
                                // get file content from edittext
                                writeByteToUri(uri, dumpExportByte);
                                //String message = "file written to external shared storage: " + uri.toString();
                                writeToUiToast("binary file written to external shared storage: " + uri.toString());
                            } catch (IOException e) {
                                e.printStackTrace();
                                writeToUiToast("ERROR: " + e.toString());
                                return;
                            }
                        }
                    }
                }
            });

    private boolean writeByteToUri(Uri uri, byte[] data) throws IOException {
        try (OutputStream outputStream = contextSave.getContentResolver().openOutputStream(uri);) {
            outputStream.write(data);
            outputStream.close();
            return true;
        } catch (Exception e) {
            System.out.println("*** EXCEPTION: " + e);
            return false;
        }
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {

            if (!mNfcAdapter.isEnabled())
                showWirelessSettings();

            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_activity_main, menu);

        MenuItem mExportMail = menu.findItem(R.id.action_export_mail);
        mExportMail.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                //Intent i = new Intent(MainActivity.this, AddEntryActivity.class);
                //startActivity(i);
                exportDumpMail();
                return false;
            }
        });

        MenuItem mExportFile = menu.findItem(R.id.action_export_file);
        mExportFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                //Intent i = new Intent(MainActivity.this, AddEntryActivity.class);
                //startActivity(i);
                exportDumpFile();
                return false;
            }
        });

        MenuItem mExportBinaryFile = menu.findItem(R.id.action_export_binary_file);
        mExportBinaryFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                //Intent i = new Intent(MainActivity.this, AddEntryActivity.class);
                //startActivity(i);
                exportBinaryDumpFile();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

}