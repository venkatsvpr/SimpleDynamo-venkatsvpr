package edu.buffalo.cse.cse486586.simpledynamo;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StreamCorruptedException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Formatter;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;

import android.content.ContentProvider;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

public class SimpleDynamoProvider extends ContentProvider {
    static Object querylock = new Object();
    static boolean queryproceed = false;
    String myPort = null;
    Integer myIndex = -1;
    static int bulk_put_count =3;
    static HashMap<String, String> avdname = new HashMap<String, String>();
    static final String[] remote_port_arr = new String[]{"11124", "11112", "11108", "11116", "11120"};
    static final String[] sorted_hash_arr = new String[]{"11124", "11112", "11108", "11116", "11120"};
    /*new String[]{"11124", "11112", "11108", "11116", "11120"}; */
    /* References:
       1) My Code imported from simpledht
       2) Oracle/Android documentation
       3) No code copied.
       4) I dont know what to write here! will fill later :) good day!
       5) Idea : https://stackoverflow.com/questions/5694385/getting-the-filenames-of-all-files-in-a-folder
     */
    public void put_data(String key, String value) {
        Log.d("venkat", "doing put data ");
        FileOutputStream outputStream;
        try {
            if ((value != null) && (key != null)) {
                Log.d("venkat", "openFileOutput - Success - File: " + key + "data" + value);
                outputStream = getContext().openFileOutput(key, Context.MODE_PRIVATE);
                outputStream.write(value.getBytes());
                outputStream.close();
            } else {
                Log.d("venkat", "write failed due to some reason");
            }
        } catch (Exception e) {
            Log.e("venkat", "File write failed");
        }
    }

    public String get_data(String selection) {
        Log.d("venkat", "doi get_data " + selection);
        String message = null;
        Log.v("query", selection);
        InputStream is = null;
        try {
            is = getContext().openFileInput(selection);
            InputStreamReader is_Reader = new InputStreamReader(is);
            BufferedReader b_Reader = new BufferedReader(is_Reader);
            message = b_Reader.readLine();
            b_Reader.close();
            is_Reader.close();
            is.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return message;
    }

    public boolean containskey(String selection) {
        Log.d("venkat", "going to do contains key" + selection);
        InputStream is = null;
        try {
            is = getContext().openFileInput(selection);
            is.close();
            return true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }


    public void remove_data(String selection) {
        Log.d("venkat", "going to do remove_Data on " + selection);
        File directory = getContext().getFilesDir();
        File file = new File(directory, selection);
        if (file.exists()) {
            Log.d("venkat", "file exists  deleting the same");
            file.delete();
        }
        return;
    }


    private MatrixCursor getMyValues(MatrixCursor mCursor) {
        /* Reference :
         */
        int count = 0;

        File dir = getContext().getFilesDir();
        File[] files = dir.listFiles();

        for (File file : files) {
            if (file.isFile()) {
                String key = file.getName();
                String value = get_data(key);
                Log.d("venkat", key + ":" + value);
                mCursor.addRow(new String[]{key, value});
                Log.d("venkat", "[" + key + "]:" + value);
                count += 1;
            }
        }
        Log.d("venkat", "getMyValues: " + count);

        return mCursor;
    }
    private boolean getMyValuesCount() {
        File dir = getContext().getFilesDir();
        File[] files = dir.listFiles();

        for (File file : files) {
            if (file.isFile()) {
                Log.d("venkat"," getmyvaluescount returning true");
                return true;
            }
        }


        Log.d("venkat"," getmyvaluescount returning false");
        return false;
    }


    private void deleteMyValues() {
        File dir = getContext().getFilesDir();
        File[] files = dir.listFiles();

        for (File file : files) {
            if (file.isFile()) {
                Log.d("venkat", "deleting .." + file.getName());
                file.delete();
            }
        }
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        synchronized (querylock) {
            Log.d("venkat"," in delete queryproceed is ... "+queryproceed);
            if (queryproceed == false) {
                try {
                    Log.d("venkat"," waiting for lock ..... ");
                    querylock.wait();
                    Log.d("venkat"," lock obtained ..... ");
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

        // TODO Auto-generated method stub
        if (selection.equals("@")) {
            deleteMyValues();
        } else if (selection.equals("*")) {
            deleteMyValues();
            for (int i = 0; i < 4; i++) {
                if (myPort.equals(remote_port_arr[i])) {
                    continue;
                }
                String ret = send_message(remote_port_arr[i], "@", "delete-local");
            }
        } else {
            String key_val = selection;

            String[] owners = new String[0];
            try {
                owners = findKeyOwner(key_val);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            String message = null;
            message = send_message(owners[0], selection, "delete");
            String message2 = send_message(owners[1], selection, "force-delete");
            String message3 = send_message(owners[2], selection, "force-delete");

        }
        return 0;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        synchronized (querylock) {
            Log.d("venkat"," in delete queryproceed is ... "+queryproceed);
            if (queryproceed == false) {
                try {
                    Log.d("venkat"," waiting for lock ..... ");
                    querylock.wait();
                    Log.d("venkat"," lock obtained ..... ");
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
        String key_val = values.getAsString("key");
        String data = values.getAsString("value");
        String[] owners = new String[0];
        try {
            owners = findKeyOwner(key_val);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        Log.d("venkat", "uri insert key: " + key_val + " data: " + data + " own " + owners[0] + " " + owners[1] + " " + owners[2]);

        String message = null;

        if (myPort.equals(owners[0])) {
            put_data(key_val, data);
        }
        else {
            message = send_message(owners[0], key_val + ":" + data, "put");
        }

        if (myPort.equals(owners[1])) {
            put_data(key_val, data);
        }
        else {
            String message2 = send_message(owners[1], key_val + ":" + data, "force-put");
        }

        if (myPort.equals(owners[2])) {
            put_data(key_val,data);
        }
        else {
            String message3 = send_message(owners[2], key_val + ":" + data, "force-put");
        }
        return uri;
    }

    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub
        Context context = getContext();
        TelephonyManager tel = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        myPort = String.valueOf((Integer.parseInt(portStr) * 2));
        myIndex = Arrays.asList(sorted_hash_arr).indexOf(myPort);

        Log.d("venkat", "venkat my port is " + myPort+" "+portStr);

        avdname.put("11108", "5554");
        avdname.put("11112", "5556");
        avdname.put("11116", "5558");
        avdname.put("11120", "5560");
        avdname.put("11124", "5562");

        ServerSocket serverSocket = null;
        try {
            serverSocket = new ServerSocket(10000);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            e.printStackTrace();
        }


        return false;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {

        // TODO Auto-generated method stub
        synchronized (querylock) {
            Log.d("venkat","queryproceed is ... "+queryproceed);
            if (queryproceed == false) {
                try {
                    Log.d("venkat"," waiting for lock ..... ");
                    querylock.wait();
                    Log.d("venkat"," lock obtained ..... ");
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

        MatrixCursor mCursor = null;
        mCursor = new MatrixCursor(new String[]{"key", "value"});

        if (selection.equals("@")) {
            mCursor = getMyValues(mCursor);
        } else if (selection.equals("*")) {
            mCursor = getMyValues(mCursor);
            for (int i = 0; i < 4; i++) {
                if (myPort.equals(remote_port_arr[i])) {
                    continue;
                }
                String ret = send_message(remote_port_arr[i], "*", "all");
                if (ret != null) {
                    if (!ret.equals("ack")) {
                        Log.d("venkat", "peer responded to all with :" + ret);
                        String[] split_tokens = ret.split("#");
                        for (int j = 0; j < split_tokens.length; j++) {
                            String[] kv_tokens = split_tokens[j].split(":");
                            if (kv_tokens.length == 2) {
                                mCursor.addRow(new String[]{kv_tokens[0], kv_tokens[1]});
                            }
                        }
                    }
                }
            }
        } else {
            String[] owners = new String[0];
            try {
                owners = findKeyOwner(selection);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            String value = null;
            String ret = null;
            if (!owners[2].equals(myPort)) {
                ret = send_message(owners[2], selection, "get");
                if (ret != null) {
                    if (!ret.equals("ack")) {
                        String[] split_tokens = ret.split("#");
                        String[] kv_tokens = split_tokens[1].split(":");
                        if (kv_tokens.length == 2) {
                            Log.d("venkat", " key :" + kv_tokens[0] + " value:" + kv_tokens[1]);
                            if (!kv_tokens[1].equals("null")) {
                            /* think of a situation when 2 is old.. and 1 is new..how will you replicate */
                                Log.d("venkat", "keys value not equal to null ");
                                value = kv_tokens[1];
                                mCursor.addRow(new String[]{kv_tokens[0], kv_tokens[1]});
                                return mCursor;
                            }
                        }
                    }
                }
            }
            else {
                if (containskey(selection)) {
                    value = get_data(selection);
                    mCursor.addRow(new String[]{selection,value});
                    return mCursor;
                }
            }


            ret = null;
            if (!owners[1].equals(myPort)) {
                ret = send_message(owners[1], selection, "get");
            }
            else {
                if (containskey(selection)) {
                    value = get_data(selection);
                    send_message(owners[2], selection + ":" + value, "force-put");
                    send_message(owners[0], selection + ":" + value, "force-put");
                    mCursor.addRow(new String[]{selection, value});
                    return mCursor;
                }
            }

            ret = send_message(owners[1], selection, "get");
            if (ret != null) {
                if (!ret.equals("ack")) {
                    String[] split_tokens = ret.split("#");
                    String[] kv_tokens = split_tokens[1].split(":");
                    if (kv_tokens.length == 2) {
                        Log.d("venkat", " key :" + kv_tokens[0] + " value:" + kv_tokens[1]);
                        if (!kv_tokens[1].equals("null")) {
                            send_message(owners[2], kv_tokens[0] + ":" + kv_tokens[1], "force-put");
                            send_message(owners[0], kv_tokens[0] + ":" + kv_tokens[1], "force-put");
                            Log.d("venkat", "keys value not equal to null ");
                            value = kv_tokens[1];
                            mCursor.addRow(new String[]{kv_tokens[0], kv_tokens[1]});
                            return mCursor;
                        }
                    }
                }
            }

            if (!owners[0].equals(myPort)) {
                ret = send_message(owners[0], selection, "get");
            }
            else {
                if (containskey(selection)) {
                    value = get_data(selection);
                    send_message(owners[2], selection + ":" + value, "force-put");
                    send_message(owners[0], selection + ":" + value, "force-put");
                    mCursor.addRow(new String[]{selection, value});
                    return mCursor;
                }
            }
            if (ret != null) {
                if (!ret.equals("ack")) {
                    String[] split_tokens = ret.split("#");
                    String[] kv_tokens = split_tokens[1].split(":");
                    if (kv_tokens.length == 2) {
                        Log.d("venkat", " key :" + kv_tokens[0] + " value:" + kv_tokens[1]);
                        if (!kv_tokens[1].equals("null")) {
                            send_message(owners[2], kv_tokens[0] + ":" + kv_tokens[1], "force-put");
                            send_message(owners[1], kv_tokens[0] + ":" + kv_tokens[1], "force-put");
                            Log.d("venkat", "keys value not equal to null ");
                            value = kv_tokens[1];
                            mCursor.addRow(new String[]{kv_tokens[0], kv_tokens[1]});
                            return mCursor;
                        }
                    }
                }
            }
            mCursor.addRow(new String[]{selection, null});
        }
        return mCursor;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection,
                      String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {
        private Uri mUri;
        private ContentResolver mContentResolver;
        private ContentValues cv = new ContentValues();

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            try {
                if (getMyValuesCount()) {
                    deleteMyValues();
                    Log.d("venkat","going to do initi data recovery");
                    String[] prev_nodes = get2prev();
                    String[] next_nodes = get2next();

                    String retval = null;
                    retval = send_message(next_nodes[1], prev_nodes[0] + ":" + myPort, "get-range");
                    if (retval != null) {
                        String []split_tokens = retval.split("#");
                        for (int j = 0; j < split_tokens.length; j++) {
                            String[] kv_tokens = split_tokens[j].split(":");
                            if (kv_tokens.length == 2) {
                                if (kv_tokens[1] != null){
                                    Log.d("venkat", "key :" + kv_tokens[0] + " value :" + kv_tokens[1]);
                                    put_data(kv_tokens[0], kv_tokens[1]);
                                }
                            }
                        }
                    }

                    retval = send_message(next_nodes[0], prev_nodes[0] + ":" + myPort, "get-range");
                    if (retval != null) {
                        String []split_tokens = retval.split("#");
                        for (int j = 0; j < split_tokens.length; j++) {
                            String[] kv_tokens = split_tokens[j].split(":");
                            if (kv_tokens.length == 2) {
                                if (kv_tokens[1] != null){
                                    Log.d("venkat", "key :" + kv_tokens[0] + " value :" + kv_tokens[1]);
                                    put_data(kv_tokens[0], kv_tokens[1]);
                                }
                            }
                        }
                    }

                    retval = send_message(next_nodes[0], prev_nodes[1] + ":" + prev_nodes[0], "get-range");
                    if (retval != null) {
                        String []split_tokens = retval.split("#");
                        for (int j = 0; j < split_tokens.length; j++) {
                            String[] kv_tokens = split_tokens[j].split(":");
                            if (kv_tokens.length == 2) {
                                if (kv_tokens[1] != null){
                                    Log.d("venkat", "key :" + kv_tokens[0] + " value :" + kv_tokens[1]);
                                    put_data(kv_tokens[0], kv_tokens[1]);
                                }
                            }
                        }
                    }


                    retval = send_message(prev_nodes[0], prev_nodes[1] + ":" + prev_nodes[0], "get-range");
                    if (retval != null) {
                        String []split_tokens = retval.split("#");
                        for (int j = 0; j < split_tokens.length; j++) {
                            String[] kv_tokens = split_tokens[j].split(":");
                            if (kv_tokens.length == 2) {
                                if (kv_tokens[1] != null){
                                    Log.d("venkat", "key :" + kv_tokens[0] + " value :" + kv_tokens[1]);
                                    put_data(kv_tokens[0], kv_tokens[1]);
                                }
                            }
                        }
                    }



                    retval = send_message(prev_nodes[0], next_nodes[1] + ":" + prev_nodes[1], "get-range");
                    if (retval != null) {
                        String []split_tokens = retval.split("#");
                        for (int j = 0; j < split_tokens.length; j++) {
                            String[] kv_tokens = split_tokens[j].split(":");
                            if (kv_tokens.length == 2) {
                                if (kv_tokens[1] != null){
                                    Log.d("venkat", "key :" + kv_tokens[0] + " value :" + kv_tokens[1]);
                                    put_data(kv_tokens[0], kv_tokens[1]);
                                }
                            }
                        }
                    }


                    retval = send_message(prev_nodes[1], next_nodes[1] + ":" + prev_nodes[1], "get-range");
                    if (retval != null) {
                        String []split_tokens = retval.split("#");
                        for (int j = 0; j < split_tokens.length; j++) {
                            String[] kv_tokens = split_tokens[j].split(":");
                            if (kv_tokens.length == 2) {
                                if (kv_tokens[1] != null){
                                    Log.d("venkat", "key :" + kv_tokens[0] + " value :" + kv_tokens[1]);
                                    put_data(kv_tokens[0], kv_tokens[1]);
                                }
                            }
                        }
                    }



                    Log.d("venkat","done with init syncup");


                }
                synchronized (querylock) {
                    queryproceed = true;
                    querylock.notifyAll();
                }
                //new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, mess2, myPort);
                 /*
                 try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                } */
                ServerSocket serverSocket = sockets[0];
                Socket accept = null;
                while (true) {
                    accept = serverSocket.accept();
                    DataInputStream in = new DataInputStream(accept.getInputStream());
                    String message = null;
                    message = in.readUTF();
                    String[] split_tokens = message.split("#");
                    Log.d("venkat", "Reading Message from accept " + accept);
                    if (message == null) {
                        Log.d("venkat", "null message read skip");
                        continue;
                    }

                    Log.d("venkat", " Message is : " + message);
                    if (split_tokens[0].equals("put")) {
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();
                        String keyvalue = split_tokens[1];
                        String[] new_split_tokens = keyvalue.split(":");
                        String key = new_split_tokens[0];
                        String val = new_split_tokens[1];

                        String[] nextpeer = get2next();

                        put_data(key, val);

                        send_message(nextpeer[0], split_tokens[1], "force-put");
                        send_message(nextpeer[1], split_tokens[1], "force-put");


                    } else if (split_tokens[0].equals("force-put")) {
                        String keyvalue = split_tokens[1];
                        String[] new_split_tokens = keyvalue.split(":");
                        String key = new_split_tokens[0];
                        String val = new_split_tokens[1];
                        put_data(key, val);
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();
                    } else if (split_tokens[0].equals("all")) {
                        String outString = "";
                        File dir = getContext().getFilesDir();
                        File[] files = dir.listFiles();
                        for (File file : files) {
                            if (file.isFile()) {
                                String key = file.getName();
                                String value = get_data(key);
                                outString += key;
                                outString += ":";
                                outString += value;
                                outString += "#";
                            }
                        }
                        if (outString == null) {
                            outString = "ack";
                        }
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF(outString);
                        out_print.flush();
                    } else if (split_tokens[0].equals("get")) {
                        String keyvalue = split_tokens[1];
                        String[] new_split_tokens = keyvalue.split(":");
                        String key = new_split_tokens[0];
                        String val = get_data(key);
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("get-reply" + "#" + key + ":" + val + "#" + myPort);
                        out_print.flush();
                    } else if (split_tokens[0].equals("delete-local")) {
                        deleteMyValues();
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();
                    } else if (split_tokens[0].equals("force-delete")) {
                        remove_data(split_tokens[1]);
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();
                    } else if (split_tokens[0].equals("delete")) {
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();

                        String key = split_tokens[1];
                        remove_data(key);
                        String[] nextpeer = get2next();
                        send_message(nextpeer[0], split_tokens[1], "force-delete");
                        send_message(nextpeer[1], split_tokens[1], "force-delete");

                    } else if (split_tokens[0].equals("get-range")) {
                        Log.d ("venkat", "processing  get-range"+split_tokens[2]);
                        String to = split_tokens[2];
                        String rangevalue = split_tokens[1];
                        String[] new_split_tokens = rangevalue.split(":");
                        String start = new_split_tokens[0];
                        String end = new_split_tokens[1];

                        String outString = "";
                        File dir = getContext().getFilesDir();
                        File[] files = dir.listFiles();
                        for (File file : files) {
                            if (file.isFile()) {
                                String key = file.getName();
                                String keyhash = null;
                                try {
                                    keyhash = genHash(key);
                                } catch (NoSuchAlgorithmException e) {
                                    e.printStackTrace();
                                }

                                if (hash_in_range(keyhash, start, end)) {
                                    String value = get_data(key);
                                    outString += key;
                                    outString += ":";
                                    outString += value;
                                    outString += "#";
                                }
                            }
                        }
                        if (outString == null) {
                            outString = "ack#";
                        }
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF(outString);
                        out_print.flush();

                        //outString = to+"!"+"bulk-put#"+outString+myPort;
                        //new BulkSend().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, outString, myPort);
                    } else if (split_tokens[0].equals("get-local")) {
                        Log.d ("venkat", "processing  get-local"+split_tokens[2]);
                        String to = split_tokens[2];
                        String outString = "";
                        File dir = getContext().getFilesDir();
                        File[] files = dir.listFiles();
                        for (File file : files) {
                            if (file.isFile()) {
                                String key = file.getName();
                                String keyhash = null;
                                try {
                                    keyhash = genHash(key);
                                } catch (NoSuchAlgorithmException e) {
                                    e.printStackTrace();
                                }
                                try {
                                    if (hashInRange(keyhash)) {
                                        String value = get_data(key);
                                        outString += key;
                                        outString += ":";
                                        outString += value;
                                        outString += "#";
                                    }
                                } catch (NoSuchAlgorithmException e) {
                                    e.printStackTrace();
                                }
                            }
                        }
                        if (outString == null) {
                            outString = "ack#";
                        }
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF(outString);
                        out_print.flush();

                        //outString = to+"!"+"bulk-put#"+outString+myPort;
                        //new BulkSend().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, outString, myPort);
                    }
                    else if (split_tokens[0].equals("bulk-put")) {
                        for (int j = 1; j < split_tokens.length; j++) {
                            String[] kv_tokens = split_tokens[j].split(":");
                            if (kv_tokens.length == 2) {
                                Log.d("venkat","key :"+kv_tokens[0]+" value :"+kv_tokens[1]);
                                remove_data(kv_tokens[0]);
                                put_data(kv_tokens[0], kv_tokens[1]);
                            }
                        }
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();
                        bulk_put_count--;
                        if (bulk_put_count <= 0) {
                            synchronized (querylock) {
                                queryproceed = true;
                                querylock.notifyAll();
                            }
                            bulk_put_count = 3;
                        }
                    }

                }
            } catch (SocketTimeoutException e) {
                Log.e("venkat", "ClientTask timeout");

            } catch (EOFException e) {
                Log.e("venkat", "ClientTask eof");
            } catch (StreamCorruptedException e) {
                Log.e("venkat", "stream corrupt");
            } catch (IOException e) {
                Log.e("venkat", "ClientTask socket IOException");
            }
            String output_message = "summa";
            publishProgress(new String[]{output_message});
            return null;
        }

        protected void onProgressUpdate(String... strings) {
            Log.d("venkat", "in publish progress");
            return;
        }
    }

    public String[] get2next() {
        if (myIndex < 0) {
            Log.d("venkat", " myIndex is negative something is seriously wrong....");
        }

        String[] retArr = new String[]{"", ""};
        if ((myIndex >= 0) && (myIndex <= 2)) {
            retArr[0] = sorted_hash_arr[myIndex + 1];
            retArr[1] = sorted_hash_arr[myIndex + 2];
        } else if (myIndex == 3) {
            retArr[0] = sorted_hash_arr[4];
            retArr[1] = sorted_hash_arr[0];
        } else if (myIndex == 4) {
            retArr[0] = sorted_hash_arr[0];
            retArr[1] = sorted_hash_arr[1];
        }
        Log.d("venkat", " my port is :" + myPort + " next ports are :" + retArr[0] + " " + retArr[1]);
        return retArr;
    }

    public String[] get2prev() {
        if (myIndex < 0) {
            Log.d("venkat", " myIndex is negative something is seriously wrong....");
        }

        String[] retArr = new String[]{"", ""};

        if ((myIndex >= 2) && (myIndex <= 4)) {
            retArr[0] = sorted_hash_arr[myIndex - 1];
            retArr[1] = sorted_hash_arr[myIndex - 2];
        } else if (myIndex == 1) {
            retArr[0] = sorted_hash_arr[0];
            retArr[1] = sorted_hash_arr[4];
        } else if (myIndex == 0) {
            retArr[0] = sorted_hash_arr[4];
            retArr[1] = sorted_hash_arr[3];
        }
        Log.d("venkat", " my port is :" + myPort + " prev ports are :" + retArr[0] + " " + retArr[1]);
        return retArr;
    }

    private boolean hashInRange(String hash) throws NoSuchAlgorithmException {
        String[] prev_items = get2prev();
        String end_hash = genHash(avdname.get(myPort));
        String start_hash = genHash(avdname.get(prev_items[0]));

        if (start_hash.compareTo(end_hash) < 0) {
            if ((start_hash.compareTo(hash) < 0) && (end_hash.compareTo(hash) > 0)) {
                Log.d("venkat", " hash " + hash + " in the start: " + start_hash + " end:" + end_hash);
                return true;
            }
        }

        if (start_hash.compareTo(end_hash) > 0) {
            if ((start_hash.compareTo(hash) < 0) || (end_hash.compareTo(hash) > 0)) {
                Log.d("venkat", " hash " + hash + " in the start: " + start_hash + " end:" + end_hash);
                return true;
            }
        }

        Log.d("venkat", " hash " + hash + "  not in the : " + start_hash + " end:" + end_hash);
        return false;
    }

    private boolean hash_in_range(String hash, String start, String end) {
        String start_hash = null;
        String end_hash = null;
        try {
            start_hash = genHash(avdname.get(start));
            end_hash = genHash(avdname.get(end));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        Log.d("venkat", "checking if hash is in between " + start_hash + " and " + end_hash + " input hash " + hash);

        if (start_hash.compareTo(end_hash) < 0) {
            if ((start_hash.compareTo(hash) < 0) && (end_hash.compareTo(hash) > 0)) {
                return true;
            }
        }

        if (start_hash.compareTo(end_hash) > 0) {
            if ((start_hash.compareTo(hash) < 0) || (end_hash.compareTo(hash) > 0)) {
                return true;
            }
        }
        return false;
    }

    public String[] findKeyOwner(String key) throws NoSuchAlgorithmException {
        String hash = genHash(key);
        String[] owners = new String[]{"", "", ""};

        if (hash_in_range(hash, sorted_hash_arr[4], sorted_hash_arr[0])) {
            owners[0] = sorted_hash_arr[0];
            owners[1] = sorted_hash_arr[1];
            owners[2] = sorted_hash_arr[2];
            return owners;
        }

        for (int i = 1; i <= 4; i++) {
            if (hash_in_range(hash, sorted_hash_arr[i - 1], sorted_hash_arr[i])) {
                owners[0] = sorted_hash_arr[i];
                owners[1] = sorted_hash_arr[(i + 1) % 5];
                owners[2] = sorted_hash_arr[(i + 2) % 5];
                return owners;
            }
        }
        return owners;
    }

    private String send_message(String port, String selection, String method) {
        try {
            Log.d("venkat", "send message: port: " + port + " selection: " + selection + " method:" + method);
            Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                    Integer.parseInt(port));
            socket.setSoTimeout(750);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeUTF(method + "#" + selection + "#" + myPort);
            out.flush();

            DataInputStream in = new DataInputStream(socket.getInputStream());
            String message = null;
            message = in.readUTF();
            Log.d("venkat", "Read ack reply:" + message);
            out.close();
            in.close();
            socket.close();
            Log.d("venkat", " myport: " + myPort);
            return message;
        }  catch (SocketTimeoutException e) {
            Log.e("venkat", "ClientTask timeout");

        } catch (EOFException e) {
            Log.e("venkat", "ClientTask eof");
        } catch (StreamCorruptedException e) {
            Log.e("venkat", "stream corrupt");
        } catch (IOException e) {
            Log.e("venkat", "ClientTask socket IOException");
        } catch (RuntimeException e) {
            Log.e("venkat", "runtime expception have to handle it here");
        }

        return null;
    }

    private class ClientTask extends AsyncTask<String, Void, Void> {
        @Override
        protected Void doInBackground(String... msgs) {

            //deleteMyValues();
/*
            try {
                Thread.sleep(1500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
  */
            String[] prev_nodes = get2prev();
            String retval = null;

            Log.d("venkat","getting local data from :"+prev_nodes[0]);
            retval = client_send_message(prev_nodes[0], "*", "get-local");
            retval = client_send_message(prev_nodes[1], "*", "get-local");

            String[] next_nodes = get2next();
            retval = client_send_message(next_nodes[0], prev_nodes[0] + ":" + myPort, "get-range");
            retval = client_send_message(next_nodes[1], prev_nodes[0] + ":" + myPort, "get-range");

            return null;
        }
        private String client_send_message(String port, String selection, String method) {
            try {
                Log.d("venkat", "send message: port: " + port + " selection: " + selection + " method:" + method);
                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(port));
                socket.setSoTimeout(200);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                out.writeUTF(method + "#" + selection + "#" + myPort);
                out.flush();

                DataInputStream in = new DataInputStream(socket.getInputStream());
                String message = null;
                message = in.readUTF();
                Log.d("venkat", "Read ack reply:" + message);
                out.close();
                in.close();
                socket.close();
                Log.d("venkat", " myport: " + myPort);
                return message;
            } catch (SocketTimeoutException e) {
                Log.e("venkat", "ClientTask timeout");

            } catch (EOFException e) {
                Log.e("venkat", "ClientTask eof");
            } catch (StreamCorruptedException e) {
                Log.e("venkat", "stream corrupt");
            } catch (IOException e) {
                Log.e("venkat", "ClientTask socket IOException");
            } catch (RuntimeException e) {
                Log.d ("venkat", "runtime excpetion.. dont panic..  ##change me afterwards ");
            }

            return null;
        }
    }


    private class BulkSend extends AsyncTask<String, Void, Void> {
        @Override
        protected Void doInBackground(String... msgs) {
            String message = msgs[0];
            Log.d("venkat"," in bulk send "+message);
            String[] split_tokens = message.split("!");
            String retval = bulk_send_message(split_tokens[0], split_tokens[1]);
            return null;
        }
        private String bulk_send_message(String port, String selection) {
            try {
                Log.d("venkat","sending message to peer "+port);
                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(port));
                socket.setSoTimeout(200);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                out.writeUTF(selection + "#" + myPort);
                out.flush();

                DataInputStream in = new DataInputStream(socket.getInputStream());
                String message = null;
                message = in.readUTF();
                Log.d("venkat", "Read ack reply:" + message);
                out.close();
                in.close();
                socket.close();
                Log.d("venkat", " myport: " + myPort);
                return message;
            } catch (SocketTimeoutException e) {
                Log.e("venkat", "ClientTask timeout");

            } catch (EOFException e) {
                Log.e("venkat", "ClientTask eof");
            } catch (StreamCorruptedException e) {
                Log.e("venkat", "stream corrupt");
            } catch (IOException e) {
                Log.e("venkat", "ClientTask socket IOException");
            }

            return null;
        }
    }
}
