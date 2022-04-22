/**************************************************************************************************/
/*                                                                                                */
/* milter-regex-ip-prep                                                                           */
/*                                                                                                */
/* Copyright (C) 2022 Takao Abe.  All rights reserved.                                            */
/*                                                                                                */
/* License: GPLv3                                                                                 */
/*                                                                                                */
/*   This program is free software: you can redistribute it and/or modify                         */
/*   it under the terms of the GNU General Public License as published by                         */
/*   the Free Software Foundation, either version 3 of the License, or                            */
/*   (at your option) any later version.                                                          */
/*                                                                                                */
/*   This program is distributed in the hope that it will be useful,                              */
/*   but WITHOUT ANY WARRANTY; without even the implied warranty of                               */
/*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                                         */
/*   See the GNU General Public License for more details.                                         */
/*                                                                                                */
/*   You should have received a copy of the GNU General Public License                            */
/*   along with this program.  If not, see <https://www.gnu.org/licenses/>.                       */
/*                                                                                                */
/* ChangeLog:                                                                                     */
/* 2022/04/17  New                                                                                */
/*                                                                                                */
/* Build: cc -Wall -o milter-regex-ip-prep milter-regex-ip-prep.c                                 */
/*                                                                                                */
/* Usage:                                                                                         */
/*                                                                                                */
/*   (1) Download IP address allocation lists from the RIR ( Regianl Internet Registry )          */
/*                                                                                                */
/*   ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest                             */
/*   ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-latest                                   */
/*   ftp://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest                             */
/*   ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest                                */
/*   ftp://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest                                */
/*                                                                                                */
/*   (2) Convert IP address allocation lists from ASCII format to binary format                   */
/*                                                                                                */
/*   cat delegated-*-latest | grep '|..|ipv[46]|' | sort -t '|' -k 3,4 | ./milter-regex-ip-prep ipv4.dat ipv6.dat */
/*                                                                                                */
/**************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <netdb.h>
#include <arpa/inet.h>

typedef unsigned char uchar ;

struct IPv4file {
    char    sCountryCode[2] ;
    uchar   bIPv4Address[4] ;
    uint    iCount ;
} ;

struct IPv6file {
    char    sCountryCode[2] ;
    uchar   bIPv6Prefix[8] ;
    uint    iCidr ;
} ;

/**************************************************************************************************/

static void help()
{

    char    *sDoc[] = {
        "",
        "NAME",
        "milter-regex-ip-prep - milter-regex IP address list preprocessor",
        "",
        "SYNOPSIS",
        "milter-regex-ip-prep IPv4OutputFile IPv6OutputFile",
        "",
        "DESCRIPTION",
        "Read IP address allocation list from standard input, and convert a record",
        "from ACSII format to binary format.",
        "",
        "USAGE",
        "(1) Download IP address allocation lists from the RIR ( Regianl Internet Registry )",
        "",
        "ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest",
        "ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-latest",
        "ftp://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
        "ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
        "ftp://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
        "",
        "(2) Convert IP address allocation lists from ASCII format to binary format",
        "",
        "cat delegated-*-latest | grep '|..|ipv[46]|' | sort -t '|' -k 3,4 | /usr/local/sbin/milter-regex-ip-prep ipv4.dat ipv6.dat",
        "",
        "FILES",
        "Standard input",
        "\tSee downloaded IP address allocation lists.",
        "\t'|' seperated ASCII data.",
        "\t1st. field: RIR",
        "\t2nd. field: Country code, ISO-3166",
        "\t3rd. field: Allocated resource, only 'ipv4' and 'ipv6' are processed, others are ignored.",
        "\t4th. field: IP address",
        "\t5th. field: Number of IP addresses for IPv4 or CIDR for IPv6",
        "",
        "IPv4OutputFile",
        "\tBinary data, 12 Bytes / 1 Record",
        "\t+--+--+--+--+--+--+--+--+--+--+--+--+",
        "\t|Code |   IPv4    |     |   Count   |",
        "\t+--+--+--+--+--+--+--+--+--+--+--+--+",
        "",
        "IPv6OutputFile",
        "\tBinary data, 16 Bytes / 1 Record",
        "\t+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+",
        "\t|Code |         IPv6          |     |   CIDR    |",
        "\t+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+",
        "",
        NULL } ;

    int     i, j ;
    bool    bTitle ;

    for ( i = 0 ; i < sizeof(sDoc) / sizeof(char*) ; i ++ ) {
        if ( sDoc[i] == NULL ) {
            break ;
        } else {
            bTitle = true ;
            for ( j = 0 ; j < strlen( sDoc[i] ) ; j ++ ) {
                if ( ! isupper( *(sDoc[i]+j) ) ) {
                    bTitle = false ;
                    break ;
                }
            }
            if ( ! bTitle ) printf( "\t" ) ;
            puts( sDoc[i] ) ;
        }
    }

}

/**************************************************************************************************/

int main( int ac, char *av[] )
{

    FILE    *pFileIn, *pFileOut4, *pFileOut6 ;
    char    sLine[100] ;
    char    *pToken[5] ;
    int     i, rc, iCount, iCidr ;
    unsigned char ipaddress[sizeof(struct in6_addr)] ;

    struct IPv4file vIPv4 ;
    struct IPv6file vIPv6 ;

    if ( ac != 3 ) {
        help( ) ;
        exit( 1 ) ;
    }

    pFileIn = fdopen( 0, "r" ) ;
    if ( pFileIn == NULL ) {
        fputs( "Open error: stdin\n", stderr ) ;
        exit( 1 ) ;
    }

    pFileOut4 = fopen( av[1], "w" ) ;
    if ( pFileOut4 == NULL ) {
        fprintf( stderr, "Open error: %s\n", av[1] ) ;
        exit( 1 ) ;
    }

    pFileOut6 = fopen( av[2], "w" ) ;
    if ( pFileOut6 == NULL ) {
        fprintf( stderr, "Open error: %s\n", av[2] ) ;
        exit( 1 ) ;
    }

    memset( &vIPv4, 0, sizeof(vIPv4) ) ;
    memset( &vIPv6, 0, sizeof(vIPv6) ) ;

    while ( fgets( sLine, sizeof( sLine ), pFileIn ) != NULL ) {

        if ( sLine[0] == '"' ) continue ;

        pToken[0] = strtok( sLine, "|" ) ;
        for ( i = 1 ; i < sizeof(pToken) / sizeof(char*) ; i ++ ) {
            if ( pToken[i-1] == NULL ) {
                pToken[i] = NULL ;
            } else {
                pToken[i] = strtok( NULL, "|" ) ;
            }
        }

        if ( pToken[1] == NULL || pToken[2] == NULL || pToken[3] == NULL || pToken[4] == NULL) {
            continue ;
        } else if ( strlen( pToken[1] ) != 2 ) {
            continue ;
        } else if ( strcmp( pToken[2], "ipv4" ) == 0 ) {
            /* ASCII -> Network */
            rc = inet_pton( AF_INET, pToken[3], ipaddress ) ;
            if ( rc != 1 ) {
                fprintf( stderr,"ERROR: [%s] | [%s] | [%s] X ( Not AF_INET ) | [%s]\n", pToken[1], pToken[2], pToken[3], pToken[4] ) ;
                continue ;
            }
            /* iNumberOfAddresses */
            iCount = atoi( pToken[4] ) ;
            if ( iCount % 16 != 0 ) {
                fprintf( stderr,"ERROR: [%s] | [%s] | [%s] | [%s] X ( Not divisible by 16 )\n", pToken[1], pToken[2], pToken[3], pToken[4] ) ;
                continue ;
            }
            /* Output */
            memcpy( vIPv4.sCountryCode, pToken[1], sizeof(vIPv4.sCountryCode) ) ;
            memcpy( vIPv4.bIPv4Address, ipaddress, sizeof(vIPv4.bIPv4Address) ) ;
            vIPv4.iCount = iCount ;
            rc = fwrite( &vIPv4, sizeof(vIPv4), 1, pFileOut4 ) ;
            if ( rc != 1 ) {
                fputs( "ERROR: fwrite\n", stderr ) ;
            }
        } else if ( strcmp( pToken[2], "ipv6" ) == 0 ) {
            rc = inet_pton( AF_INET6, pToken[3], ipaddress ) ;
            if ( rc != 1 ) {
                fprintf( stderr,"ERROR: [%s] | [%s] | [%s] X ( Not AF_INET6 ) | [%s]\n", pToken[1], pToken[2], pToken[3], pToken[4] ) ;
                continue ;
            }
            /* CIDR */
            iCidr = atoi( pToken[4] ) ;
            if ( iCidr < 16 || 64 < iCidr ) {
                fprintf( stderr,"ERROR: [%s] | [%s] | [%s] | [%s] X ( Invalid CIDR )\n", pToken[1], pToken[2], pToken[3], pToken[4] ) ;
                continue ;
            }
            /* Output */
            memcpy( vIPv6.sCountryCode, pToken[1], sizeof(vIPv6.sCountryCode) ) ;
            memcpy( vIPv6.bIPv6Prefix , ipaddress, sizeof(vIPv6.bIPv6Prefix ) ) ;
            vIPv6.iCidr = iCidr ;
            rc = fwrite( &vIPv6, sizeof(vIPv6), 1, pFileOut6 ) ;
            if ( rc != 1 ) {
                fputs( "ERROR: fwrite\n", stderr ) ;
            }
        }

    }

    fclose( pFileIn ) ;
    fclose( pFileOut4 ) ;
    fclose( pFileOut6 ) ;

}

/**************************************************************************************************/
