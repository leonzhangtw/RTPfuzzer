Real-time Transport Protocol(RTP) Fuzzer Tools 
===


# Description
針對即時傳輸協定(RTP)所開發的自動化模糊測試工具
本工具適用於Linux、Windows、MacOS作業系統上執行
建議使用Python 2.7.x環境執行
下載後，目錄內會以下四個檔案


* README.TXT 說明檔
* LOG.TXT 執行後，測試過程的日誌檔
* rtp.conf 參數設定檔
* rtpfuzz.py 檢測程式


測試目的為造成Server端在解析封包過程中發生錯誤，造成設備重新開機或其他異常行為，驗證IOT設備是否存在被Client端所發出的封包造成服務中斷的弱點。


# Features
針對RTP協定中定義的Header對各欄位增加額外隨機產生的字元進行測試，例如'Sequence number'、'timestamp'、'SSRC/CSRC'等欄位進行Fuzzing Test



# Usage
## Step1:設定參數檔rtp.conf
1.RHOST改成設備IP address
2.RPORT為RTP的服務PORT，RTP沒有預設保留port，需到設備管理介面裡面查看。
3.JUNK和DELAY欄位使用預設即可。
4.MSFPATTERN保持預設為ON不需更改，此模式為讓模糊測試執行時會隨機產生payload，就不會只產生不同數量的JUNK字元(ex.AAAAAAAAAAAA)
5.STOPAFTER為模糊測試的測試筆數，規範門檻為10萬筆。

Example:
```bash=
[rtpfuzz]
#IP or Host name of the Remote host
RHOST : 192.168.1.56

#RTP Service port (Depend on Device)
RPORT : 554

#Junk Bytes to USE (Don't use more than one character at a time like AAAA   BBBB).
JUNK : A

#Time Delay in Seconds between two requests 
DELAY : 0

#Use Metasploit pattern for fuzzing
#if its ON then it will use metasploit pattern as junk data for fuzzing instead of AAA/BBB etc etc
#using metasploit pattern when fuzzing helps to find offset
#Warning:Turning this feature on may take some extra time for fuzzing.

MSFPATTERN : ON
# terminate value
STOPAFTER : 1000000
```


## STEP2
將參數檔設定完畢後，即可開始執行程式。
```
python rtpfuzz.py
```
## STEP3
程式執行完成後

打開log.txt確認測試過程中完整性，檢查測試筆數是否有達到10萬筆或八小時的標準

# Reference
ITEF RFC-3550文件:https://tools.ietf.org/html/rfc3550