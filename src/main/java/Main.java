import com.mongodb.*;
import com.mongodb.util.JSON;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class Main {
    private static final String KEY = "43exampleKey123"; // VirusShare API KEY
    private static final String PATH = "D:\\Malware Samples\\406 hash values.txt"; // Path to '.txt' file containing the hash values to search
    private static final File FILE = new File(PATH);

    private static int lineCount = 0;
    private static int reportsStored = 0;
    private static List<String> hashValues;
    private static DBCollection collection;

    public static void main(String[] args) {
        if (!FILE.exists()) {
            System.exit(0);
        }

        lineCount = getLineCount();
        hashValues = getLines();

        dbSetup();
        requestFileReports();
    }

    /**
     * Connects to the local MongoDB database "virusshare_reports" and retrieves the collection "md5-406".
     */
    private static void dbSetup() {
        try {
            MongoClient mongoClient = new MongoClient();
            DB db = mongoClient.getDB("virusshare_reports"); //DB name
            collection = db.getCollection("md5-406"); //Collection name
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    /**
     * add JSON result to collection in db.
     *
     * @param result from API request
     */
    private static void addObject(ByteArrayOutputStream result) {
        String resultStr = String.valueOf(result);
        StringBuilder sb = new StringBuilder(resultStr);
        sb.insert(1, "\"result\": {");

        DBObject obj = (DBObject) JSON.parse(sb.toString());
        collection.insert(obj);
        reportsStored++;
        System.out.println("Result added.\nNumber of reports stored: " + reportsStored);
    }

    /**
     * Requests reports from VirusShare.
     * 5760 daily limit, 4 searches per minute.
     * 15 second wait meets both restrictions.
     */
    private static void requestFileReports() {
        for (int i = 0; i < lineCount; i++) {

            InputStream response;
            try {
                String urlString = "https://virusshare.com/apiv2/file?apikey=" + KEY + "&hash=";
                URL url = new URL(urlString + hashValues.get(i));

                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                response = connection.getInputStream();

                ByteArrayOutputStream result = new ByteArrayOutputStream();

                byte[] buffer = new byte[1024];

                for (int length; (length = response.read(buffer)) != -1; ) { //write content of buffer to result
                    result.write(buffer, 0, length);
                }

                result.write('}'); //end of JSON file
                addObject(result);

            } catch (IOException e) {
                e.printStackTrace();
            }

            try {
                TimeUnit.SECONDS.sleep(15); //delay to stop rate limiting
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * @return List of hash values from the hash list text file, returns the first 5760 values found.
     */
    private static List<String> getLines() {
        List<String> lines = null;
        try {
            lines = Files.readAllLines(Path.of(PATH));
        } catch (IOException e) {
            e.printStackTrace();
        }

        assert lines != null;
        if (lines.size() > lineCount) {
            lines.subList(lineCount, lines.size()).clear(); //remove all values after daily max
        }

        return lines;
    }

    private static int getLineCount() {
        try {
            lineCount = (int) Files.lines(Path.of(PATH)).count();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return lineCount;
    }
}