/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <osquery/tables.h>

#include "osquery/tables/networking/utils.h"

namespace osquery {
namespace tables {

QueryData genInterfaceBonds(QueryContext& context) {
  Row r;
  QueryData results;

/* Read data from /sys/class/net/bonding_masters file and check for the bond name.*/
FILE *read,*read2,*read3,*read4,*read5,*read6,*read7,*read8,*read9,*read10,*read11,*read12,*read13,*read14,*read15;

      read = fopen("/sys/class/net/bonding_masters","r");
      if (read==NULL) {fputs ("File error",stderr); exit (1);}
      char bond[20];
      fscanf(read,"%s",bond);
      r["bond"] = TEXT(bond);
      fclose(read);

/* Read data from /sys/class/net/bond0/bonding/primary file and check the primary interface of the bond. */
      read2 = fopen("/sys/class/net/bond0/bonding/primary","r");
      if (read2==NULL) {fputs ("File error",stderr); exit (1);}
      char primary[5];
      fscanf(read2,"%s",primary);
      r["primary"] = TEXT(primary);
      fclose(read2);

/* Read data from /sys/class/net/bond0/bonding/slaves file for the name of the network interfaces used for the bond. */
     read3 = fopen("/sys/class/net/bond0/bonding/slaves","rt");
     if (read3==NULL) {fputs ("File error",stderr); exit (1);}
     char interfaces[25];
     fgets(interfaces,25,read3);
     r["interfaces"] = TEXT(interfaces);
     fclose(read3);

/* Read data from /sys/class/net/bond0/bonding/mode file and displays the bond mode. */
      read4 = fopen("/sys/class/net/bond0/bonding/mode","r");
      if (read4==NULL) {fputs ("File error",stderr); exit (1);}
      char mode[50];
      fscanf(read4,"%s",mode);
      r["mode"] = TEXT(mode);
      fclose(read4);

/* Read data from /sys/class/net/bond0/type file and displays the type of bond. */
      read15 = fopen("/sys/class/net/bond0/type","r");
      if (read15==NULL) {fputs ("File error",stderr); exit (1);}
      char type[10];
      fscanf(read15,"%s",type);
      r["type"] = BIGINT(type);
      fclose(read15);

/* Read data from /sys/class/net/bond0/bonding/mii_status file and displays the status of the network interfaces used in the bond. */
      read5 = fopen("/sys/class/net/bond0/bonding/mii_status","r");
      if (read5==NULL) {fputs ("File error",stderr); exit (1);}
      char status[10];
      fscanf(read5,"%s",status);
      r["mii_status"] = TEXT(status);
      fclose(read5);

/* Read data from /sys/class/net/bond0/speed file and displays the bond speed. */
      read6 = fopen("/sys/class/net/bond0/speed","r");
      if (read6==NULL) {fputs ("File error",stderr); exit (1);}
      char speed[20];
      fscanf(read6,"%s",speed);
      r["speed"] = BIGINT(speed);
      fclose(read6);

/* Read data from /sys/class/net/bond0/duplex file and displays the bond duplex mode. */
      read7 = fopen("/sys/class/net/bond0/duplex","r");
      if (read7==NULL) {fputs ("File error",stderr); exit (1);}
      char duplex[5];
      fscanf(read7,"%s",duplex);
      r["duplex"] = TEXT(duplex);
      fclose(read7);

/* Read data from /sys/class/net/bond0/statistics/tx_errors file and displays errors in bond transmition. */
      read8 = fopen("/sys/class/net/bond0/statistics/tx_errors","r");
      if (read8==NULL) {fputs ("File error",stderr); exit (1);}
      char tx_errors[50];
      fscanf(read8,"%s",tx_errors);
      r["tx_errors"] = BIGINT(tx_errors);
      fclose(read8);

/* Read data from /sys/class/net/bond0/statistics/rx_errors file and displays errors in bond reception. */
      read9 = fopen("/sys/class/net/bond0/statistics/rx_errors","r");
      if (read9==NULL) {fputs ("File error",stderr); exit (1);}
      char rx_errors[50];
      fscanf(read9,"%s",rx_errors);
      r["rx_errors"] = BIGINT(rx_errors);
      fclose(read9);

/* Read data from /sys/class/net/bond0/statistics/tx_bytes file and displays bytes transmitted by the bond. */
      read10 = fopen("/sys/class/net/bond0/statistics/tx_bytes","r");
      if (read10==NULL) {fputs ("File error",stderr); exit (1);}
      char tx_bytes[50];
      fscanf(read10,"%s",tx_bytes);
      r["tx_bytes"] = BIGINT(tx_bytes);
      fclose(read10);

/* Read data from /sys/class/net/bond0/statistics/rx_bytes file and displays bytes received by the bond. */
      read11 = fopen("/sys/class/net/bond0/statistics/rx_bytes","r");
      if (read11==NULL) {fputs ("File error",stderr); exit (1);}
      char rx_bytes[50];
      fscanf(read11,"%s",rx_bytes);
      r["rx_bytes"] = BIGINT(rx_bytes);
      fclose(read11);

/* Read data from /sys/class/net/bond0/bonding/queue_id file and displays the queue id for the slaves of the bond. */
      read12 = fopen("/sys/class/net/bond0/bonding/queue_id","r");
      if (read12==NULL) {fputs ("File error",stderr); exit (1);}
      char queue_id[50];
      fgets(queue_id,50,read12);
      r["queue_id"] = TEXT(queue_id);
      fclose(read12);

/* Read data from /sys/class/net/bond0/bonding/active_slave file and displays the active slave interface of the bond. */
      read13 = fopen("/sys/class/net/bond0/bonding/active_slave","r");
      if (read13==NULL) {fputs ("File error",stderr); exit (1);}
      char active_slave[5];
      fscanf(read13,"%s",active_slave);
      r["active_slave"] = TEXT(active_slave);
      fclose(read13);

/* Read data from /sys/class/net/bond0/bonding/miimon file and displays the frequency in milliseconds of MII monitoring. */
      read14 = fopen("/sys/class/net/bond0/bonding/miimon","r");
      if (read14==NULL) {fputs ("File error",stderr); exit (1);}
      char miimon[10];
      fscanf(read14,"%s",miimon);
      r["miimon"] = BIGINT(miimon);
      fclose(read14);

results.push_back(r);
  return results;
}
}
}
