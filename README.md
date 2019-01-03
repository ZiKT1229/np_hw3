# np_hw3

請設計一支pcap封包檔的讀取程式，可以讀入pcap檔，並列出檔案中每個封包的來源/目的IP位址、來源/目的port號碼、封包長度、時間(以年、月、日、時、分、秒等單位 顯示)。

另外，command line當中可以設定過濾條件(BPF 語法的條件)，使你的讀取程式只會顯示滿足條件的封包。

ps. pcap檔的範例可在https://wiki.wireshark.org/SampleCaptures 下載。

參考: https://stackoverflow.com/questions/13503224/getting-wrong-ip-and-port-number-from-libpcap-captured-packet