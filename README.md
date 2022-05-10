# VirusShare-Report-Extractor
Used to query the VirusShare API to retrieve malware reports for a given list of malware sample MD5 hash values.
Lists containing the MD5 hash values for each sample contained within VirusShare torrents can be found under virusshare.com/hashes.

Reports are stored in a local MongoDB collection. The default database name is "virusshare_reports", the default collection is name\d "md5-406".
Before running the application, ensure the database & collection are hosted locally on the machine. The attribtues "KEY" and "PATH" should be set before runtime.
