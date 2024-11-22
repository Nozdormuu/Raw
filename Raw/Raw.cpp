#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define ICMP_ECHO 8
#define ICMP_ECHO_REPLY 0
#define ICMP_HEADER_SIZE 8
#define DEFAULT_TIMEOUT 1000 
#define BUFFER_SIZE 1024


typedef struct {
   BYTE Type;        
   BYTE Code;        
   USHORT Checksum;  
   USHORT ID;        
   USHORT Sequence;  
} ICMPHeader;

USHORT checksum(USHORT* buffer, int size) {
   unsigned long cksum = 0;
   while (size > 1) {
      cksum += *buffer++;
      size -= sizeof(USHORT);
   }
   if (size) {
      cksum += *(UCHAR*)buffer;
   }
   cksum = (cksum >> 16) + (cksum & 0xffff);
   cksum += (cksum >> 16);
   return (USHORT)(~cksum);
}

int main() {
   system("chcp 65001");
   WSADATA wsaData;
   SOCKET rawSocket;
   struct sockaddr_in dest;
   char sendBuf[ICMP_HEADER_SIZE + sizeof(DWORD)];
   char recvBuf[BUFFER_SIZE];
   ICMPHeader* icmpHeader;
   DWORD timestamp;
   int timeout = DEFAULT_TIMEOUT;
   int destLen = sizeof(dest);
   const char* target = "127.0.0.1"; 

   
   if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
      printf("Ошибка инициализации Winsock\n");
      return 1;
   }

   // Создание сырого сокета
   rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
   if (rawSocket == INVALID_SOCKET) {
      printf("Ошибка создания сокета: %d\n", WSAGetLastError());
      WSACleanup();
      return 1;
   }

   setsockopt(rawSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

   
   memset(&dest, 0, sizeof(dest));
   dest.sin_family = AF_INET;
   if (inet_pton(AF_INET, target, &(dest.sin_addr)) != 1) {
      printf("Не удалось преобразовать адрес %s\n", target);
      closesocket(rawSocket);
      WSACleanup();
      return 1;
   }

   
   icmpHeader = (ICMPHeader*)sendBuf;
   icmpHeader->Type = ICMP_ECHO;
   icmpHeader->Code = 0;
   icmpHeader->ID = (USHORT)GetCurrentProcessId();
   icmpHeader->Sequence = 1;
   timestamp = GetTickCount64();
   memcpy(sendBuf + ICMP_HEADER_SIZE, &timestamp, sizeof(timestamp));
   icmpHeader->Checksum = 0;
   icmpHeader->Checksum = checksum((USHORT*)sendBuf, sizeof(sendBuf));

   
   int numPackets = 4; // Количество пакетов для отправки

   for (int i = 0; i < numPackets; i++) {
      
      icmpHeader->Sequence = i + 1;
      
      timestamp = GetTickCount64();
      memcpy(sendBuf + ICMP_HEADER_SIZE, &timestamp, sizeof(timestamp));
      
      icmpHeader->Checksum = 0;
      icmpHeader->Checksum = checksum((USHORT*)sendBuf, sizeof(sendBuf));

      // Отправка ICMP пакета
      if (sendto(rawSocket, sendBuf, sizeof(sendBuf), 0, (struct sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR) {
         printf("Ошибка отправки пакета: %d\n", WSAGetLastError());
         closesocket(rawSocket);
         WSACleanup();
         return 1;
      }

      // Ожидание ответа
      if (recvfrom(rawSocket, recvBuf, sizeof(recvBuf), 0, (struct sockaddr*)&dest, &destLen) == SOCKET_ERROR) {
         if (WSAGetLastError() == WSAETIMEDOUT) {
            printf("Превышено время ожидания.\n");
         }
         else {
            printf("Ошибка при получении ответа: %d\n", WSAGetLastError());
         }
      }
      else {
         // Анализ ответа
         ICMPHeader* recvIcmpHeader = (ICMPHeader*)(recvBuf + (recvBuf[0] & 0x0F) * 4);
         if (recvIcmpHeader->Type == ICMP_ECHO_REPLY && recvIcmpHeader->ID == icmpHeader->ID && recvIcmpHeader->Sequence == icmpHeader->Sequence) {
            DWORD recvTimestamp;
            memcpy(&recvTimestamp, recvBuf + (recvBuf[0] & 0x0F) * 4 + ICMP_HEADER_SIZE, sizeof(recvTimestamp));
            printf("Ответ от %s: номер %d, время=%dмс\n", target, recvIcmpHeader->Sequence, GetTickCount64() - recvTimestamp);
         }
         else {
            printf("Получен некорректный ответ.\n");
         }
      }    
      // Задержка перед следующей отправкой
      Sleep(1000);
   }

   closesocket(rawSocket);
   WSACleanup();
   return 0;

}
