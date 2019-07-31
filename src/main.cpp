/* Based on example from hackster.io:   https://www.hackster.io/p99will/esp32-wifi-mac-scanner-sniffer-promiscuous-4c12f4
   Inspired by Paxcounter               https://github.com/cyberman54/ESP32-Paxcounter
   and some help from                   https://github.com/ESP-EOS/ESP32-WiFi-Sniffer/blob/master/WIFI_SNIFFER_ESP32.ino
*/
#include <WiFi.h>
#include <Wire.h>

#include "esp_wifi.h"

#define maxCh 13         //max Channel -> US = 11, EU = 13, Japan = 14
uint8_t curChannel = 1;
 int listcount = 0;
String maclist[64][3];
int8_t rssi_limit = -97;

/* String KnownMac[10][2] =
{ // Put devices you want to be reconized
  {"Hewlett Packard", "FC3FDB"},
  {"Combal Broad Networks Inc", "DC537C"},
  {"One Plus Tech", "C0EEFB"},
  {"Xiaomi Communications", "A45046"},
  {"Apple Inc", "E4E4AB"},
  {"NAME", "MACADDRESS"},
  {"NAME", "MACADDRESS"},
  {"NAME", "MACADDRESS"},
  {"NAME", "MACADDRESS"}
}; */

typedef struct // Struct voor de MAC Header
{
  unsigned frame_ctrl: 16;
  unsigned duration: 16;
  uint8_t da[6];    //receiver address
  uint8_t sa[6];    // sender address
  uint8_t bssid[6]; // filtering address
  unsigned sequence_ctrl: 16;
  uint8_t addr4[6]; // Optional?
} mac_hdr_t;

typedef struct // Struct voor de WiFi packeten
{ 
  mac_hdr_t hdr;
  uint8_t payload[0];
} wifi_packet_t;

const wifi_promiscuous_filter_t filt = // filter the packets with type of WIFI_PKT_MGMT | filter the packets with type of WIFI_PKT_DATA
    {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA 
};

void add_mac(String addr, int8_t rssi)
{
 
  bool added = false;


  for (int i = 0; i <= 63; i++)  
  { 
    if (addr == maclist[i][0]) // checks if the MAC address has been added before
    {
      if(maclist[i][1] == "OFFLINE") // Check if it was offline and has come back to reset timer
      {
        maclist[i][1] = "0";
      }
      //Serial.println("OLD mac: " + addr + " with an rssi of -" + maclist[listcount][2]);
      //Serial.println(" ");
      added = true;
    }
  }

  if (!added) // if not added voeg een nieuw MAC addres toe.
  {
    maclist[listcount][0] = addr;
    maclist[listcount][1] = "0";
    maclist[listcount][2] = abs(rssi);
    //Serial.println("NEW mac: " + addr + " with an rssi of -" + maclist[listcount][2]);
    //Serial.println(" ");
    listcount++;

    if (listcount >= 64) // MAC array heeft x aantal plaatsen check als deze vol zit daarna resetten. 
    {
      Serial.println("Mac array full resetting!");
      listcount = 0;
    }
  }
}
/**
  * @brief The RX callback function in the promiscuous mode. 
  *        Each time a packet is received, the callback function will be called.
  *
  * @param buf  Data received. Type of data in buffer (wifi_promiscuous_pkt_t or wifi_pkt_rx_ctrl_t) indicated by 'type' parameter.
  * @param type  promiscuous packet type.
  *
  */

// using IRAM_:ATTR here to speed up callback function
IRAM_ATTR void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) //Dit is de callback function waar de WiFi packeten naar toe gestuurd worden.
{
  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  const wifi_packet_t *snifed_packed = (wifi_packet_t *)pkt->payload;
  const mac_hdr_t *mac_header = &snifed_packed->hdr;

  const uint16_t pkt_length = pkt->rx_ctrl.sig_len - sizeof(mac_hdr_t);


  if (pkt->rx_ctrl.rssi < rssi_limit || pkt_length < 0) // Controleer of signaal(RSSI) goed genoeg is > 0. RSSI is niet altijd volledig betrouwbaar
  {                                   // aangezien verschillende fabrikanten andere waardes gebruiken. 0-60, 0-255, ...
    //Serial.printf("WiFi RSSI %d lower than limit %d, ignoring packet.\n", pkt->rx_ctrl.rssi, rssi_limit);
  }
  else
  {
    
/*     Serial.printf("CHAN=%02d, RSSI=%02d, SA=%02x:%02x:%02x:%02x:%02x:%02x\n", pkt->rx_ctrl.channel, pkt->rx_ctrl.rssi, 
    mac_header->sa[0],mac_header->sa[1],mac_header->sa[2], mac_header->sa[3],mac_header->sa[4],mac_header->sa[5]); */

    String mac_to_str;
    for (uint8_t i = 0; i < 6; i++)
    {
      mac_to_str += String(mac_header->sa[i], HEX);
    }
    //Serial.println(mac_to_str);
    add_mac(mac_to_str, pkt->rx_ctrl.rssi); // Signaal goed genoeg toevoegen maar!
  }
} //Sniffer

//===== SETUP =====//
void setup()
{

  /* start Serial */
  Serial.begin(115200);

  /* setup wifi */
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);

  Serial.println("starting!");
}

void updatetime()
{ 
  for (int i = 0; i <= 63; i++)
  {
    if (!(maclist[i][0] == "")) // check if mac is set
    {
      if (!(maclist[i][2].toInt() < rssi_limit)) // check if rssi  -80
      {
        maclist[i][1] = String(maclist[i][1].toInt() + 1);
      }
      else
      {
        maclist[i][1] = "OFFLINE";
      }
    }
  }
}

void showpeople()
{
  for (int i = 0; i <= 63; i++)
  {
    if (!(maclist[i][0] == ""))
    {
      //for (int j = 0; j <= 9; j++)
      //{
        //String tmp1 = (String)maclist[i][0];
        //String tmp2 = KnownMac[j][1];
        //if (tmp1 == tmp2)
        //{
          //Serial.printf("Recognized! -> %s : %s : %d : %d \n", KnownMac[j][0], tmp1, maclist[i][2], maclist[i][1]); // Print recognized MAC NAME : MAC : RSSI : TIMER
          //Serial.println("Recognized! -> " + KnownMac[j][0] + " : " + tmp1 + " : " + maclist[i][2] + " : " + maclist[i][1]);
        //}
        //else
        //{
          //Serial.printf("%s : %d : %d \n", tmp1, maclist[i][2], maclist[i][1]); // Print MAC : RSSI : TIMER
          String active = (maclist[i][1] == "OFFLINE") ? "." : "s.";
          Serial.println("MAC: " + maclist[i][0] + " RSSi: -" + maclist[i][2] + " ACTIVE: " + maclist[i][1] + active);
        //}
      }
    }
  Serial.println(" ");
}

//===== LOOP =====//
void loop()
{
  Serial.println("--------------------------------------------------------");
  Serial.println("Changed channel:" + String(curChannel));
  if (curChannel > maxCh)
  {
    curChannel = 1;
  }
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  delay(1000);
  updatetime();
  showpeople();
  curChannel++;
}