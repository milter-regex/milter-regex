/**************************************************************************************************/
/*                                                                                                */
/* geoip.c                                                                                        */
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
/**************************************************************************************************/
/*                                                                                                */
/* RIR ( Regianl Internet Registry ) IP address allocation data                                   */
/*                                                                                                */
/*   '|' seperated ASCII data.                                                                    */
/*   1st. field: RIR                                                                              */
/*   2nd. field: Country code, ISO-3166                                                           */
/*   3rd. field: Allocated resource, only 'ipv4' and 'ipv6' are processed, others are ignored.    */
/*   4th. field: IP address                                                                       */
/*   5th. field: Number of IP addresses for IPv4 or CIDR for IPv6                                 */
/*   6th. field and later are ignored.                                                            */
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
/* IPv4file record format:                                                                        */
/*                                                                                                */
/*   Binary data, 12 Bytes / 1 Record                                                             */
/*   +--+--+--+--+--+--+--+--+--+--+--+--+                                                        */
/*   |Code |   IPv4    |     |   Count   |                                                        */
/*   +--+--+--+--+--+--+--+--+--+--+--+--+                                                        */
/*                                                                                                */
/* IPv6file record format:                                                                        */
/*                                                                                                */
/*   Binary data, 16 Bytes / 1 Record                                                             */
/*   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+                                            */
/*   |Code |         IPv6          |     |   CIDR    |                                            */
/*   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+                                            */
/*                                                                                                */
/**************************************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Private data type definision */

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

struct IPcash {
    void    *pNode ;                /* ByteTreeNode */
    void    *pNext ;                /* CashChain in the ByteTreeNode */
    void    *pBack ;                /* CashChain in the ByteTreeNode */
    void    *pNextCash ;            /* CashChain for deleteing in FIFO order */
    void    *pBackCash ;            /* CashChain for deleteing in FIFO order */
    time_t  tCashTimestamp ;
    char    sCountryCode[2] ;       /* ISO-3166 | '??': Unknown */
    uchar   bAddress[8] ;           /* IPv4: 0-3 | IPv6: 0-7 ( Prefix only ) */
    uint    iCount ;                /* IPv4 allocation */
    ushort  iCidr ;                 /* IPv6 allocation */
} ;

struct ByteTreeNode {
    char    iIPversion ;            /* 4 or 6       */
    char    iOctetNumber ;          /* 1 to 8       */
    void    *pUpperNode ;           /* ByteTreeNode */
    void    *pLowerNodeIndex[256] ; /* ByteTreeNode */
    void    *pCashChainFirst ;      /* CashChain    */
    void    *pCashChainLast ;       /* CashChain    */
    int     iLowerNodeCount ;
    int     iCashChainCount ;
} ;

/* Constants */

#define CASH_MIN  102400L       /* Minimum cash size ( iCashMax >= This value ) */

#define DEFAULT_CASH_MAX    CASH_MIN
#define DEFAULT_CASH_KEEP   (7*86400)

/* Internal variables are set by the global functions */

char    sIPv4CashFile[1024] ;   /* Conf file keyword: ipv4file */
char    sIPv6CashFile[1024] ;   /* Conf file keyword: ipv6file */

bool    bEnableGeoIP ;          /* Conf file keyword: Both ipv4file and ipv6file */
ulong   iCashMax ;              /* Conf file keyword: geoipCashMax  */
time_t  tCashKeep ;             /* Conf file keyword: geoipCashKeep */
int     iDebugLogLevel ;        /* Conf file keyword: geoipDebugLog */

/* Internal variables */

static  ulong   iCashSize ;

static  struct  ByteTreeNode  *pIPv4ByteTreeRoot ;
static  struct  ByteTreeNode  *pIPv6ByteTreeRoot ;

static  struct  IPcash        *pCashChainFirst ;
static  struct  IPcash        *pCashChainLast ;

struct  {
    uint    iIPv4FileAccess ;   /* Increment when cach miss and file is accessed */
    uint    iIPv6FileAccess ;   /* Increment when cach miss and file is accessed */
    uint    iIPv4CashHit ;      /* Increment when cach hit */
    uint    iIPv6CashHit ;      /* Increment when cach hit */
    uint    iIPv4CashExpire ;   /* Increment when cach hit but expired */
    uint    iIPv6CashExpire ;   /* Increment when cach hit but expired */
    uint    iIPv4CashPurge ;    /* Increment when cach is purged before expired */
    uint    iIPv6CashPurge ;    /* Increment when cach is purged before expired */
    int     iIPv4NodeCount ;
    int     iIPv6NodeCount ;
    int     iIPv4CashCount ;
    int     iIPv6CashCount ;
} vCashStat ;

static  bool    bDailyStatLog ;
struct  tm      tmDailyStatLog ;

/* Global function prototype */

void init_geoip( ) ;
int  get_CountryCode( const char *, char[3] ) ;   /* Return country code into 2nd. param. */
int  check_geoipEnabled( ) ;                      /* 0: Enabled / 1: Disabled */

void reset_geoip( ) ;
void set_ipv4file( const char * ) ;
void set_ipv6file( const char * ) ;
void set_geoipCashMax( const char * ) ;
void set_geoipCashKeep( const char * ) ;
void set_geoipDebugLog( const char * ) ;

/* Internal function prototype */

static void           milterLog( int, const char *, ... ) ;
static void           countryIPv4( const uchar[], char[3] ) ;
static void           countryIPv6( const uchar[], char[3] ) ;
static struct IPcash* countryIPv4cash( const uchar * ) ;
static struct IPcash* countryIPv4file( const uchar * ) ;
static struct IPcash* countryIPv6cash( const uchar * ) ;
static struct IPcash* countryIPv6file( const uchar * ) ;
static bool           checkCashExpiration( time_t ) ;

static struct ByteTreeNode* createByteTreeNode( struct ByteTreeNode *, int, int ) ;
static void                 deleteByteTreeNode( struct ByteTreeNode * ) ;

static void setIPv4node  ( struct IPcash * ) ;
static void setIPv6node  ( struct IPcash * ) ;
static void purgeOldIPcash ( ) ;
static void insertIPcash ( struct IPcash * ) ;
static void removeIPcash ( struct IPcash * ) ;
static bool IsMatchIPv6Prefix( const uchar*, const uchar*, int ) ;

/**************************************************************************************************/
/*                                                                                                */
/* Standalone unit test driver                                                                    */
/*                                                                                                */
/* Build:  cc -DSTANDALONE_UNIT_TEST -Wall -o geoiptest geoip.c                                   */
/*                                                                                                */
/* Usage:  ./geoiptest 192.0.2.0 2001:db8:: 198.51.100.0 IPaddress ...                            */
/*                                                                                                */
/**************************************************************************************************/

#ifdef  STANDALONE_UNIT_TEST
int main( int ac, char *av[] )
{

    int     i ;
    char    sCountryCode[3] ;

    printf( "\nmain: sizeof(struct ByteTreeNode)=%ld sizeof(struct IPcash)=%ld\n\n", sizeof(struct ByteTreeNode), sizeof(struct IPcash) ) ;

    init_geoip( ) ;

    set_ipv4file( "/var/lib/milter-regex/ipv4.dat" ) ;
    set_ipv6file( "/var/lib/milter-regex/ipv6.dat" ) ;
    set_geoipCashMax( "100K" ) ;
    set_geoipCashKeep( "7d" ) ;
    set_geoipDebugLog( "INFO" ) ;

    //iCashMax = 30000 ;
    //tCashKeep = 1 ;

    printf( "\niCashMax=%lu tCashKeep=%lu\n\n", iCashMax, tCashKeep ) ;

    for ( i = 1 ; i < ac ; i ++ ) {

        printf( "= = = = =\n\n" ) ;

        get_CountryCode ( av[i], sCountryCode ) ;
        printf( "main: get_CountryCode [%s] -> [%s]\n", av[i], sCountryCode ) ;
        printf( "main: CashMax=%lu, CashSize=%lu, IPv4 FileAccess=%u CashHit=%u CashExpire=%u CashPurge=%u NodeCount=%d CashCount=%d, IPv6 FileAccess=%u CashHit=%u CashExpire=%u CashPurge=%u NodeCount=%d CashCount=%d",
                       iCashMax, iCashSize,
                       vCashStat.iIPv4FileAccess, vCashStat.iIPv4CashHit, vCashStat.iIPv4CashExpire, vCashStat.iIPv4CashPurge, vCashStat.iIPv4NodeCount, vCashStat.iIPv4CashCount,
                       vCashStat.iIPv6FileAccess, vCashStat.iIPv6CashHit, vCashStat.iIPv6CashExpire, vCashStat.iIPv6CashPurge, vCashStat.iIPv6NodeCount, vCashStat.iIPv6CashCount ) ;
        printf( "\n\n" ) ;

        get_CountryCode ( av[i], sCountryCode ) ;
        printf( "main: get_CountryCode [%s] -> [%s]\n", av[i], sCountryCode ) ;
        printf( "main: CashMax=%lu, CashSize=%lu, IPv4 FileAccess=%u CashHit=%u CashExpire=%u CashPurge=%u NodeCount=%d CashCount=%d, IPv6 FileAccess=%u CashHit=%u CashExpire=%u CashPurge=%u NodeCount=%d CashCount=%d",
                       iCashMax, iCashSize,
                       vCashStat.iIPv4FileAccess, vCashStat.iIPv4CashHit, vCashStat.iIPv4CashExpire, vCashStat.iIPv4CashPurge, vCashStat.iIPv4NodeCount, vCashStat.iIPv4CashCount,
                       vCashStat.iIPv6FileAccess, vCashStat.iIPv6CashHit, vCashStat.iIPv6CashExpire, vCashStat.iIPv6CashPurge, vCashStat.iIPv6NodeCount, vCashStat.iIPv6CashCount ) ;
        printf( "\n\n" ) ;

    }

}
#endif

/**************************************************************************************************/
/*                                                                                                */
/* init_geoip is called by main in the milter-regex.c                                             */
/*                                                                                                */
/**************************************************************************************************/

void init_geoip( )
{

    sIPv4CashFile[0] = 0 ;
    sIPv6CashFile[0] = 0 ;

    bEnableGeoIP = false ;

    iCashMax       = DEFAULT_CASH_MAX ;
    tCashKeep      = DEFAULT_CASH_KEEP ;
    iDebugLogLevel = LOG_DEBUG ;

    bDailyStatLog = true ;

    iCashSize = 0 ;

    pIPv4ByteTreeRoot = NULL ;
    pIPv6ByteTreeRoot = NULL ;

    pCashChainFirst = NULL ;
    pCashChainLast  = NULL ;

    memset( &vCashStat, 0, sizeof(vCashStat) ) ;
    memset( &tmDailyStatLog, 0, sizeof(tmDailyStatLog) ) ;

}

/**************************************************************************************************/
/*                                                                                                */
/* get_CountryCode is called by cb_helo in the milter-regex.c                                     */
/*                                                                                                */
/**************************************************************************************************/

int get_CountryCode( const char *sIPaddress, char sCountryCode[3] )
{

    const int RC_FOUND   = 0 ;
    const int RC_UNKNOWN = 1 ;

    uchar   aIP[16] ;
    int     rc ;

    /* Clear return string */

    sCountryCode[0] = '?' ;
    sCountryCode[1] = '?' ;
    sCountryCode[2] = 0 ;

    /* Check GeoIP enabled */

    if ( ! bEnableGeoIP ) {
        return RC_UNKNOWN ;
    }

    /* Statistics log */

    if ( bDailyStatLog ) {

        time_t  t ;
        struct  tm  tmNow ;

        t = time( NULL ) ;
        localtime_r( &t, &tmNow ) ;

        if ( tmDailyStatLog.tm_mon != tmNow.tm_mon || tmDailyStatLog.tm_mday != tmNow.tm_mday ) {

            milterLog( LOG_INFO, "Statistics GeoIP: CashMax=%lu, CashSize=%lu, IPv4 FileAccess=%u CashHit=%u CashExpire=%u CashPurge=%u NodeCount=%d CashCount=%d, IPv6 FileAccess=%u CashHit=%u CashExpire=%u CashPurge=%u NodeCount=%d CashCount=%d",
                       iCashMax, iCashSize,
                       vCashStat.iIPv4FileAccess, vCashStat.iIPv4CashHit, vCashStat.iIPv4CashExpire, vCashStat.iIPv4CashPurge, vCashStat.iIPv4NodeCount, vCashStat.iIPv4CashCount,
                       vCashStat.iIPv6FileAccess, vCashStat.iIPv6CashHit, vCashStat.iIPv6CashExpire, vCashStat.iIPv6CashPurge, vCashStat.iIPv6NodeCount, vCashStat.iIPv6CashCount ) ;

            tmDailyStatLog.tm_year = tmNow.tm_year ;
            tmDailyStatLog.tm_mon  = tmNow.tm_mon  ;
            tmDailyStatLog.tm_mday = tmNow.tm_mday ;
            tmDailyStatLog.tm_hour = tmNow.tm_hour ;
            tmDailyStatLog.tm_min  = tmNow.tm_min  ;
            tmDailyStatLog.tm_sec  = tmNow.tm_sec  ;

        }

    }

    /* Check */

    if ( sIPaddress == NULL ) {
        milterLog( LOG_ERR, "ERROR: get_CountryCode: Invalid parameter [NULL]" ) ;
        return RC_UNKNOWN ;
    }

    /* Get country code from IP address */

    if ( strchr( sIPaddress, ':' ) != NULL || strlen( sIPaddress ) > 15 ) {
        /* Probably IPv6 */
        rc = inet_pton( AF_INET6, sIPaddress, aIP ) ;
        if ( rc == 1 ) {
            /* IPv6 */
            countryIPv6( aIP, sCountryCode ) ;
        } else {
            milterLog( LOG_ERR, "ERROR: inet_pton: [%s] is presumed to be IPv6, but AF_INET6 failed.", sIPaddress ) ;
            return RC_UNKNOWN ;
        }
    } else {
        /* Probably IPv4 */
        rc = inet_pton( AF_INET, sIPaddress, aIP ) ;
        if ( rc == 1 ) {
            /* IPv4 */
            countryIPv4( aIP, sCountryCode ) ;
        } else {
            milterLog( LOG_ERR, "ERROR: inet_pton: [%s] is presumed to be IPv4, but AF_INET failed.", sIPaddress ) ;
            return RC_UNKNOWN ;
        }
    }

    milterLog( LOG_DEBUG, "get_CountryCode: [%s] [%s]", sIPaddress, sCountryCode ) ;

    return RC_FOUND ;

}

/**************************************************************************************************/
/*                                                                                                */
/*  check_geoipEnabled is called by cb_helo and get_ruleset in the milter-regex.c                 */
/*                                                                                                */
/**************************************************************************************************/

int check_geoipEnabled() 
{

    const int RC_ENABLED  = 0 ;
    const int RC_DISABLED = 1 ;

    return ( bEnableGeoIP ? RC_ENABLED : RC_DISABLED ) ;

}

/**************************************************************************************************/
/*                                                                                                */
/* reset_geoip is called by get_ruleset in milter-regex.c                                         */
/*                                                                                                */
/**************************************************************************************************/

void reset_geoip( )

{

    sIPv4CashFile[0] = 0 ;
    sIPv6CashFile[0] = 0 ;

    bEnableGeoIP = false ;

    iDebugLogLevel = LOG_DEBUG ;

    milterLog( LOG_DEBUG, "reset_geoip: Clear Cash file path and disable GeoIP check." ) ;

}

/**************************************************************************************************/
/*                                                                                                */
/* set_ipv4file, set_ipv6file, set_geoipCashMax, set_geoipCashKeep and set_geoipDebugLog          */
/* are called by action in the parse.y                                                            */
/*                                                                                                */
/**************************************************************************************************/

void set_ipv4file( const char *sFile )
{

    if ( sFile == NULL ) {
        milterLog( LOG_ERR, "ERROR: set_ipv4file: Invalid parameter [NULL]" ) ;
        return ;
    } else if ( strlen( sFile ) == 0 ) {
        milterLog( LOG_ERR, "ERROR: set_ipv4file: Filename is empty" ) ;
        return ;
    } else if ( strlen( sFile ) >= sizeof(sIPv4CashFile) - 1 ) {
        milterLog( LOG_ERR, "ERROR: set_ipv4file: Filename is too long [%d] [%s]", strlen( sFile ), sFile ) ;
        return ;
    }

    strncpy( sIPv4CashFile, sFile, sizeof(sIPv4CashFile) ) ;

    milterLog( LOG_INFO, "set_ipv4file: [%s]", sIPv4CashFile ) ;

    if ( sIPv4CashFile[0] != 0 && sIPv6CashFile[0] != 0 && ! bEnableGeoIP ) {
        bEnableGeoIP = true ;
    }

    return ;

}

void set_ipv6file( const char *sFile )
{

    if ( sFile == NULL ) {
        milterLog( LOG_ERR, "ERROR: set_ipv6file: Invalid parameter [NULL]" ) ;
        return ;
    } else if ( strlen( sFile ) == 0 ) {
        milterLog( LOG_ERR, "ERROR: set_ipv6file: Filename is empty" ) ;
        return ;
    } else if ( strlen( sFile ) >= sizeof(sIPv6CashFile) - 1 ) {
        milterLog( LOG_ERR, "ERROR: set_ipv6file: Filename is too long [%d] [%s]: ", strlen( sFile ), sFile ) ;
        return  ;
    }

    strncpy( sIPv6CashFile, sFile, sizeof(sIPv6CashFile) ) ;

    milterLog( LOG_INFO, "set_ipv6file: [%s]", sIPv6CashFile ) ;

    if ( sIPv4CashFile[0] != 0 && sIPv6CashFile[0] != 0 && ! bEnableGeoIP ) {
        bEnableGeoIP = true ;
    }

    return ;

}

void set_geoipCashMax( const char *sCashMax )
{

    char    ch ;
    ulong   k ;

    if ( sCashMax == NULL ) {
        milterLog( LOG_ERR, "ERROR: set_geoipCashMax: Invalid parameter [NULL]" ) ;
        return ;
    } else if ( strlen( sCashMax ) == 0 ) {
        milterLog( LOG_ERR, "ERROR: set_geoipCashMax: Invalid parameter [%s]", sCashMax ) ;
        return ;
    } else if ( strspn( sCashMax, "0123456789" ) == 0
             || strspn( sCashMax, "0123456789" ) < strlen( sCashMax ) - 1 ) {
        milterLog( LOG_ERR, "ERROR: set_geoipCashMax: Invalid parameter [%s]", sCashMax ) ;
        return ;
    }

    ch = toupper( sCashMax[ strlen( sCashMax ) - 1 ] ) ;

    if ( isdigit( ch ) ) {
        k = 1 ;
    } else if ( ch == 'K' ) {
        k = 1024 ;
    } else if ( ch == 'M' ) {
        k = 1024 * 1024 ;
    } else {
        milterLog( LOG_ERR, "ERROR: set_geoipCashMax: Invalid cash size unit [%s]", sCashMax ) ;
        return ;
    }

    iCashMax = atol( sCashMax ) * k ;

    if ( iCashMax < CASH_MIN ) {
        iCashMax = CASH_MIN ;
        milterLog( LOG_WARNING, "WARNING: set_geoipCashMax: [%s] CashMax=%lu ( Minimum cash is %luKB )", sCashMax, iCashMax, CASH_MIN / 1024 ) ;
    }

    milterLog( LOG_INFO, "set_geoipCashMax: [%s] CashMax=%lu (KB)", sCashMax, iCashMax / 1024 ) ;

    return ;

}

void set_geoipCashKeep( const char *sCashKeep )
{

    char    ch ;
    time_t  k ;

    if ( sCashKeep == NULL ) {
        milterLog( LOG_ERR, "ERROR: set_geoipCashKeep: Invalid parameter [NULL]" ) ;
        return ;
    } else if ( strlen( sCashKeep ) == 0 ) {
        milterLog( LOG_ERR, "ERROR: set_geoipCashKeep: Invalid parameter [%s]", sCashKeep ) ;
        return ;
    } else if ( strspn( sCashKeep, "0123456789" ) == 0
             || strspn( sCashKeep, "0123456789" ) < strlen( sCashKeep ) - 1 ) {
        milterLog( LOG_ERR, "ERROR: set_geoipCashKeep: Invalid parameter [%s]", sCashKeep ) ;
        return ;
    }

    ch = toupper( sCashKeep[ strlen( sCashKeep ) - 1 ] ) ;

    if ( isdigit( ch ) ) {
        k = 1 ;
    } else if ( ch == 'H' ) {
        k = 3600 ;
    } else if ( ch == 'D' ) {
        k = 86400 ;
    } else {
        milterLog( LOG_ERR, "ERROR: set_geoipCashKeep: Invalid cash keep time unit [%s]", sCashKeep ) ;
        return ;
    }

    tCashKeep = atol( sCashKeep ) * k ;

    if (  tCashKeep < 86400 ) {
        milterLog( LOG_INFO, "set_geoipCashKeep: [%s] CashKeep=%lu (Sec.)", sCashKeep, tCashKeep ) ;
    } else {
        milterLog( LOG_INFO, "set_geoipCashKeep: [%s] CashKeep=%lu (Hours)", sCashKeep, tCashKeep / 3600 ) ;
    }

    return ;

}

void set_geoipDebugLog( const char *sDebugLogLevel )
{

    if ( sDebugLogLevel == NULL ) {
        milterLog( LOG_ERR, "ERROR: set_geoipDebugLog: Invalid parameter [NULL]" ) ;
    } else if ( strcmp( sDebugLogLevel, "DEBUG" ) == 0 ) {
        iDebugLogLevel = LOG_DEBUG ;
        milterLog( LOG_INFO, "set_geoipDebugLog: LOG_DEBUG (DebugLogLevel=%d)", iDebugLogLevel ) ;
    } else if ( strcmp( sDebugLogLevel, "INFO" ) == 0 ) {
        iDebugLogLevel = LOG_INFO ;
        milterLog( LOG_INFO, "set_geoipDebugLog: LOG_INFO (DebugLogLevel=%d)", iDebugLogLevel ) ;
    } else {
        milterLog( LOG_ERR, "ERROR: set_geoipDebugLog: Invalid parameter [%s]", sDebugLogLevel ) ;
    }

    return ;

}

/**************************************************************************************************/
/*                                                                                                */
/* Internal functions                                                                             */
/*                                                                                                */
/**************************************************************************************************/

static void milterLog( int iLogLevel, const char *sFormat, ... )
{

    va_list   va ;
    char    sLog[1000] ;
    int     iForceLogLevel ;

    va_start( va, sFormat ) ;

    vsnprintf( sLog, sizeof(sLog), sFormat, va ) ;

    iForceLogLevel = iLogLevel ;
    if ( iForceLogLevel == LOG_DEBUG ) iForceLogLevel = iDebugLogLevel ;

#ifdef  STANDALONE_UNIT_TEST
    printf( "LogLevel=%d(%s): %s\n", iLogLevel, iLogLevel < LOG_INFO ? "ERROR" : ( iLogLevel == LOG_INFO ? "INFO" : "DEBUG" ), sLog ) ;
#else
    syslog( iForceLogLevel, "%s", sLog ) ;
#endif

    va_end( va ) ;

}

/**************************************************************************************************/

static void countryIPv4( const uchar pIPv4Address[], char sCountryCode[3] )
{

    struct  IPcash  *pIPcash ;
    bool    bExpire ;

    /* Check cash */

    pIPcash = countryIPv4cash( pIPv4Address ) ;
    if ( pIPcash != NULL ) {
        bExpire = checkCashExpiration( pIPcash->tCashTimestamp ) ;
        if ( ! bExpire ) {
            sCountryCode[0] = pIPcash->sCountryCode[0] ;
            sCountryCode[1] = pIPcash->sCountryCode[1] ;
            sCountryCode[2] = 0 ;
            return ;
        } else {
            struct  ByteTreeNode    *pByteTreeNode = pIPcash->pNode ;
            /* Remove expired IP cash */
            vCashStat.iIPv4CashExpire ++ ;
            milterLog( LOG_DEBUG, "countryIPv4cash: Cash expired" ) ;
            removeIPcash( pIPcash ) ;
            vCashStat.iIPv4CashCount -- ;
            pByteTreeNode->iCashChainCount -- ;
            /* If ByteTreeNode has no IP cash and no lower node, remove ByteTreeNode */
            if ( pByteTreeNode->iOctetNumber > 1
              && pByteTreeNode->iLowerNodeCount == 0 && pByteTreeNode->iCashChainCount == 0 ) {
                deleteByteTreeNode( pByteTreeNode ) ;
            }
        }
    }

    /* Check file */

    pIPcash = countryIPv4file( pIPv4Address ) ;
    if ( pIPcash != NULL ) {
        sCountryCode[0] = pIPcash->sCountryCode[0] ;
        sCountryCode[1] = pIPcash->sCountryCode[1] ;
        sCountryCode[2] = 0 ;
    } else {
        sCountryCode[0] = '?' ;
        sCountryCode[1] = '?' ;
        sCountryCode[2] = 0 ;
        return ;
    }

    /* Add cash */

    setIPv4node( pIPcash ) ;
    if ( pIPcash->pNode == NULL ) {
        free( pIPcash ) ;
        iCashSize -= sizeof( struct IPcash ) ;
        return ;
    }
    insertIPcash( pIPcash ) ;
    vCashStat.iIPv4CashCount ++ ;
    ((struct ByteTreeNode *)pIPcash->pNode)->iCashChainCount ++ ;

    milterLog( LOG_DEBUG, "countryIPv4: Add cash: CashMax=%lu, CashSize=%lu, IPv4FileAccess=%u, IPv4CashHit=%u, IPv4NodeCount=%d, IPv4CashCount=%d",
               iCashMax, iCashSize, vCashStat.iIPv4FileAccess, vCashStat.iIPv4CashHit, vCashStat.iIPv4NodeCount, vCashStat.iIPv4CashCount ) ;

    /* Cash limit */

    if ( iCashSize > iCashMax ) {
        purgeOldIPcash( ) ;
    }

}

/**************************************************************************************************/

static struct IPcash* countryIPv4cash( const uchar pIPv4Address[] )
{

    int     i ;
    struct  ByteTreeNode    *pByteTreeNode ;
    struct  IPcash          *pIPcash ;
    uint    iIPcheck, iIPstart, iIPend ;
    bool    bFound ;
    int     iScanCount ;

    iIPcheck = pIPv4Address[0]<<24 | pIPv4Address[1]<<16 | pIPv4Address[2]<<8 | pIPv4Address[3] ;

    pByteTreeNode = pIPv4ByteTreeRoot ;

    pIPcash = NULL ;
    bFound = false ;
    iScanCount = 0 ;

    for ( i = 0 ; i <= 3 ; i ++ ) {
        if ( pByteTreeNode == NULL ) break; 

        for ( pIPcash = pByteTreeNode->pCashChainFirst ; pIPcash != NULL ; pIPcash = pIPcash->pNext ) {

            iScanCount++ ;

            iIPstart = pIPcash->bAddress[0]<<24 | pIPcash->bAddress[1]<<16 | pIPcash->bAddress[2]<<8 | pIPcash->bAddress[3] ;
            iIPend   = iIPstart + pIPcash->iCount - 1 ;

            if ( iIPstart <= iIPcheck && iIPcheck <= iIPend ) {
                bFound = true ;
                break ;
            }

        }
        if ( bFound ) break ;

        pByteTreeNode = pByteTreeNode->pLowerNodeIndex[ pIPv4Address[i] ] ;
    }

    if ( pIPcash != NULL ) {
        vCashStat.iIPv4CashHit ++ ;
        milterLog( LOG_DEBUG, "countryIPv4cash: Cash hit ( NodeLevel=%d, ScanCount=%d )", pByteTreeNode->iOctetNumber, iScanCount ) ;
    } else {
        milterLog( LOG_DEBUG, "countryIPv4cash: Cash miss" ) ;
    }

    return pIPcash ;

}

/**************************************************************************************************/

static struct IPcash* countryIPv4file( const uchar pIPv4Address[] )
{

    FILE    *pFile ;
    struct  IPv4file    vIPv4file ;
    size_t  rc ;
    bool    bFound ;
    struct  IPcash      *pIPcash ;
    uint    iIPcheck, iIPstart, iIPend ;

    if ( sIPv4CashFile[0] == 0 ) {
        milterLog( LOG_NOTICE, "countryIPv4file: IPv4 file name is not specfied by the 'ipv4file'." ) ;
        return NULL ;
    }

    pIPcash = malloc( sizeof( struct IPcash ) ) ;
    if ( pIPcash == NULL ) {
        milterLog( LOG_ERR, "ERROR: countryIPv4file: malloc" ) ;
        return NULL ;
    }
    iCashSize += sizeof( struct IPcash ) ;

    /* Search the address allocation data of the RIR */

    pFile = fopen( sIPv4CashFile, "r" ) ;
    if ( pFile == NULL ) {
        milterLog( LOG_ERR, "ERROR: countryIPv4file: fopen [%s]", sIPv4CashFile ) ;
        return NULL ;
    }

    vCashStat.iIPv4FileAccess ++ ;

    iIPcheck = pIPv4Address[0]<<24 | pIPv4Address[1]<<16 | pIPv4Address[2]<<8 | pIPv4Address[3] ;

    bFound = false ;

    while ( ! bFound )
    {

        rc = fread( &vIPv4file, sizeof( struct IPv4file ), 1, pFile ) ;
        if ( rc == 0 ) break ;

        iIPstart = vIPv4file.bIPv4Address[0]<<24 | vIPv4file.bIPv4Address[1]<<16 | vIPv4file.bIPv4Address[2]<<8 | vIPv4file.bIPv4Address[3] ;
        iIPend   = iIPstart + vIPv4file.iCount - 1 ;

        if ( iIPstart <= iIPcheck && iIPcheck <= iIPend ) bFound = true ;

    }

    fclose( pFile ) ;

    /* Set cash data */

    if ( bFound ) {
        milterLog( LOG_DEBUG, "countryIPv4file: Data found" ) ;
        pIPcash->sCountryCode[0] = vIPv4file.sCountryCode[0] ;
        pIPcash->sCountryCode[1] = vIPv4file.sCountryCode[1] ;
        memcpy( pIPcash->bAddress, vIPv4file.bIPv4Address, ( sizeof(pIPcash->bAddress) <= sizeof(struct in_addr) ) ? sizeof(pIPcash->bAddress) : sizeof(struct in_addr) ) ;
        pIPcash->iCount = vIPv4file.iCount ;
    } else {
        milterLog( LOG_DEBUG, "countryIPv4file: Data not found" ) ;
        pIPcash->sCountryCode[0] = '?' ;
        pIPcash->sCountryCode[1] = '?' ;
        memcpy( pIPcash->bAddress, pIPv4Address, ( sizeof(pIPcash->bAddress) <= sizeof(struct in_addr) ) ? sizeof(pIPcash->bAddress) : sizeof(struct in_addr) ) ;
        /* Clear octet 4 */
        pIPcash->bAddress[3] = 0 ;
        /* Class C */
        pIPcash->iCount = 256 ;
    }

    /* Set cash timestamp */

    pIPcash->tCashTimestamp = time( NULL ) ;

    return pIPcash ;

}

/**************************************************************************************************/

static void countryIPv6( const uchar pIPv6Address[], char sCountryCode[3] )
{

    struct  IPcash  *pIPcash ;
    bool    bExpire ;

    /* Check cash */

    pIPcash = countryIPv6cash( pIPv6Address ) ;
    if ( pIPcash != NULL ) {
        bExpire = checkCashExpiration( pIPcash->tCashTimestamp ) ;
        if ( ! bExpire ) {
            sCountryCode[0] = pIPcash->sCountryCode[0] ;
            sCountryCode[1] = pIPcash->sCountryCode[1] ;
            sCountryCode[2] = 0 ;
            return ;
        } else {
            struct  ByteTreeNode    *pByteTreeNode = pIPcash->pNode ;
            /* Remove expired IP cash */
            vCashStat.iIPv6CashExpire ++ ;
            milterLog( LOG_DEBUG, "countryIPv4cash: Cash expired" ) ;
            removeIPcash( pIPcash ) ;
            vCashStat.iIPv6CashCount -- ;
            pByteTreeNode->iCashChainCount -- ;
            /* If ByteTreeNode has no IP cash and no lower node, remove ByteTreeNode */
            if ( pByteTreeNode->iOctetNumber > 1
              && pByteTreeNode->iLowerNodeCount == 0 && pByteTreeNode->iCashChainCount == 0 ) {
                deleteByteTreeNode( pByteTreeNode ) ;
            }
        }
    }

    /* Check file */

    pIPcash = countryIPv6file( pIPv6Address ) ;
    if ( pIPcash != NULL ) {
        sCountryCode[0] = pIPcash->sCountryCode[0] ;
        sCountryCode[1] = pIPcash->sCountryCode[1] ;
        sCountryCode[2] = 0 ;
    } else {
        sCountryCode[0] = '?' ;
        sCountryCode[1] = '?' ;
        sCountryCode[2] = 0 ;
        return ;
    }

    /* Add cash */

    setIPv6node( pIPcash ) ;
    if ( pIPcash->pNode == NULL ) {
        free( pIPcash ) ;
        iCashSize -= sizeof( struct IPcash ) ;
        return ;
    }
    insertIPcash( pIPcash ) ;
    vCashStat.iIPv6CashCount ++ ;
    ((struct ByteTreeNode *)pIPcash->pNode)->iCashChainCount ++ ;

    milterLog( LOG_DEBUG, "countryIPv6: Add cash: CashMax=%lu, CashSize=%lu, IPv6FileAccess=%u, IPv6CashHit=%u, IPv6NodeCount=%d, IPv6CashCount=%d",
               iCashMax, iCashSize, vCashStat.iIPv6FileAccess, vCashStat.iIPv6CashHit, vCashStat.iIPv6NodeCount, vCashStat.iIPv6CashCount ) ;

    /* Cash limit */

    if ( iCashSize > iCashMax ) {
        purgeOldIPcash( ) ;
    }

}

/**************************************************************************************************/

static struct IPcash* countryIPv6cash( const uchar pIPv6Address[] )
{

    int     i ;
    struct  ByteTreeNode    *pByteTreeNode ;
    struct  IPcash          *pIPcash ;
    bool    bFound ;
    int     iScanCount ;

    pByteTreeNode = pIPv6ByteTreeRoot ;

    pIPcash = NULL ;
    bFound = false ;
    iScanCount = 0 ;

    for ( i = 0 ; i <= 7 ; i++ ) {
        if ( pByteTreeNode == NULL ) break; 

        for ( pIPcash = pByteTreeNode->pCashChainFirst ; pIPcash != NULL ; pIPcash = pIPcash->pNext ) {

            iScanCount++ ;

            if ( IsMatchIPv6Prefix( pIPv6Address, pIPcash->bAddress, pIPcash->iCidr ) ) {
                bFound = true ;
                break ;
            }

        }
        if ( bFound ) break ;

        pByteTreeNode = pByteTreeNode->pLowerNodeIndex[ pIPv6Address[i] ] ;
    }

    if ( pIPcash != NULL ) {
        vCashStat.iIPv6CashHit ++ ;
        milterLog( LOG_DEBUG, "countryIPv6cash: Cash hit ( NodeLevel=%d, ScanCount=%d )", pByteTreeNode->iOctetNumber, iScanCount ) ;
    } else {
        milterLog( LOG_DEBUG, "countryIPv6cash: Cash miss" ) ;
    }

    return pIPcash ;

}

/**************************************************************************************************/

static struct IPcash* countryIPv6file( const uchar pIPv6Address[] )
{

    FILE    *pFile ;
    struct  IPv6file    vIPv6file ;
    size_t  rc ;
    bool    bFound ;
    struct  IPcash      *pIPcash ;

    if ( sIPv6CashFile[0] == 0 ) {
        milterLog( LOG_NOTICE, "countryIPv6file: IPv6 file name is not specfied by the 'ipv6file'." ) ;
        return NULL ;
    }

    pIPcash = malloc( sizeof( struct IPcash ) ) ;
    if ( pIPcash == NULL ) {
        milterLog( LOG_ERR, "ERROR: countryIPv6file: malloc" ) ;
        return NULL ;
    }
    iCashSize += sizeof( struct IPcash ) ;

    /* Search the address allocation data of the RIR */

    pFile = fopen( sIPv6CashFile, "r" ) ;
    if ( pFile == NULL ) {
        milterLog( LOG_ERR, "ERROR: countryIPv6file: fopen [%s]", sIPv6CashFile ) ;
        return NULL ;
    }

    vCashStat.iIPv6FileAccess ++ ;

    bFound = false ;

    while ( ! bFound )
    {

        rc = fread( &vIPv6file, sizeof( struct IPv6file ), 1, pFile ) ;
        if ( rc == 0 ) break ;

        if ( IsMatchIPv6Prefix( pIPv6Address, vIPv6file.bIPv6Prefix, vIPv6file.iCidr ) ) bFound = true ;

    }

    fclose( pFile ) ;

    /* Set cash data */

    if ( bFound ) {
        milterLog( LOG_DEBUG, "countryIPv6file: Data found" ) ;
        pIPcash->sCountryCode[0] = vIPv6file.sCountryCode[0] ;
        pIPcash->sCountryCode[1] = vIPv6file.sCountryCode[1] ;
        memcpy( pIPcash->bAddress, vIPv6file.bIPv6Prefix, ( sizeof(pIPcash->bAddress) <= sizeof(vIPv6file.bIPv6Prefix) ) ? sizeof(pIPcash->bAddress) : sizeof(vIPv6file.bIPv6Prefix) ) ;
        pIPcash->iCidr = vIPv6file.iCidr ;
    } else {
        milterLog( LOG_DEBUG, "countryIPv6file: Data not found" ) ;
        pIPcash->sCountryCode[0] = '?' ;
        pIPcash->sCountryCode[1] = '?' ;
        memcpy( pIPcash->bAddress, pIPv6Address, ( sizeof(pIPcash->bAddress) <= sizeof(vIPv6file.bIPv6Prefix) ) ? sizeof(pIPcash->bAddress) : sizeof(vIPv6file.bIPv6Prefix) ) ;
        pIPcash->iCidr = 64 ;
    }

    /* Set cash timestamp */

    pIPcash->tCashTimestamp = time( NULL ) ;

    return pIPcash ;

}

/**************************************************************************************************/

static bool checkCashExpiration( time_t tCashTimestamp )
{

    time_t  tNow ;

    tNow = time( NULL ) ;

    return ( ( tNow - tCashTimestamp) > tCashKeep ) ;

}

/**************************************************************************************************/

static void setIPv4node( struct IPcash *pIPcash )
{

    struct  ByteTreeNode    *pByteTreeNode ;
    int     i ;

    /* Root node */

    if ( pIPv4ByteTreeRoot == NULL ) {
        pIPv4ByteTreeRoot = createByteTreeNode( NULL, 4, 1 ) ;
        if ( pIPv4ByteTreeRoot == NULL ) {
            pIPcash->pNode = NULL ;
            return ;
        }
    }
    pByteTreeNode = pIPv4ByteTreeRoot ;

    /* Determine node level according to the number of IP allocation. */

    for ( i = 0 ; i <= 2 ; i ++ ) {
        if ( i == 0 && pIPcash->iCount > 16777216 ) {
            /* More than class A -> First level node chain */
            break ;
        } else if ( i == 1 && pIPcash->iCount > 65536 ) {
            /* More than class B -> Second level node chain */
            break ;
        } else if ( i == 2 && pIPcash->iCount > 256 ) {
            /* More than class C -> Third level node chain */
            break ;
        }
        /* Go to lower level node */
        if ( pByteTreeNode->pLowerNodeIndex[ pIPcash->bAddress[i] ] == NULL ) {
            pByteTreeNode->pLowerNodeIndex[ pIPcash->bAddress[i] ] = createByteTreeNode( pByteTreeNode, 4, i + 2 ) ;
            if ( pByteTreeNode->pLowerNodeIndex[ pIPcash->bAddress[i] ] != NULL ) {
                pByteTreeNode->iLowerNodeCount ++ ;
            }
        }
        pByteTreeNode = pByteTreeNode->pLowerNodeIndex[ pIPcash->bAddress[i] ] ;
        if ( pByteTreeNode == NULL ) {
            pIPcash->pNode = NULL ;
            return ;
        }
    }

    pIPcash->pNode = pByteTreeNode ;

#ifdef  STANDALONE_UNIT_TEST
    printf( "setIPv4node: NodeLevel=%d IPCount=%d\n", pByteTreeNode->iOctetNumber, pIPcash->iCount ) ;
#endif
}

/**************************************************************************************************/

static void setIPv6node( struct IPcash *pIPcash )
{

    struct  ByteTreeNode    *pByteTreeNode ;
    int     i, iCidrStep ;

    /* Root node */

    if ( pIPv6ByteTreeRoot == NULL ) {
        pIPv6ByteTreeRoot = createByteTreeNode( NULL, 4, 1 ) ;
        if ( pIPv6ByteTreeRoot == NULL ) {
            pIPcash->pNode = NULL ;
            return ;
        }
    }
    pByteTreeNode = pIPv6ByteTreeRoot ;

    for ( i = 0, iCidrStep = 0 ; iCidrStep < pIPcash->iCidr ; i++, iCidrStep += 8 ) {
        if ( pByteTreeNode->pLowerNodeIndex[ pIPcash->bAddress[i] ] == NULL ) {
            pByteTreeNode->pLowerNodeIndex[ pIPcash->bAddress[i] ] = createByteTreeNode( pByteTreeNode, 6, i + 2 ) ;
            if ( pByteTreeNode->pLowerNodeIndex[ pIPcash->bAddress[i] ] != NULL ) {
                pByteTreeNode->iLowerNodeCount ++ ;
            }
        }
        pByteTreeNode = pByteTreeNode->pLowerNodeIndex[ pIPcash->bAddress[i] ] ;
        if ( pByteTreeNode == NULL ) {
            pIPcash->pNode = NULL ;
            return ;
        }
    }

    pIPcash->pNode = pByteTreeNode ;

#ifdef  STANDALONE_UNIT_TEST
    printf( "setIPv6node: NodeLevel=%d CIDR=%d\n", pByteTreeNode->iOctetNumber, pIPcash->iCidr ) ;
#endif
}

/**************************************************************************************************/

static void purgeOldIPcash( )
{

    bool    bExpire ;
    struct  ByteTreeNode    *pByteTreeNode ;
    int     iNodeLevel ;

    ulong   iCurrentCashSize = iCashSize ;
    int     iCurrentIPv4CashPurge = vCashStat.iIPv4CashPurge ;
    int     iCurrentIPv4NodeCount = vCashStat.iIPv4NodeCount ;
    int     iCurrentIPv4CashCount = vCashStat.iIPv4CashCount ;
    int     iCurrentIPv6CashPurge = vCashStat.iIPv6CashPurge ;
    int     iCurrentIPv6NodeCount = vCashStat.iIPv6NodeCount ;
    int     iCurrentIPv6CashCount = vCashStat.iIPv6CashCount ;

    if ( iCashSize <= iCashMax ) return ;

    while ( iCashSize > iCashMax
         && pCashChainLast != NULL && pCashChainFirst != pCashChainLast ) {

        /* Remove cash, but at least 2 cashes are retained */
        if ( pCashChainFirst == pCashChainLast->pBackCash ) break ;

        pByteTreeNode = pCashChainLast->pNode ;
        bExpire = checkCashExpiration( pCashChainLast->tCashTimestamp ) ;

        removeIPcash( pCashChainLast ) ;

        switch ( pByteTreeNode->iIPversion ) {
        case 4 :
            vCashStat.iIPv4CashCount -- ;
            if ( vCashStat.iIPv4CashCount < 0 ) {
                /* Bug */
                milterLog( LOG_CRIT, "ERROR: purgeOldIPcash: vCashStat.iIPv4CashCount=%d ", vCashStat.iIPv4CashCount ) ;
                vCashStat.iIPv4CashCount = 0 ;
            }
            if ( ! bExpire ) vCashStat.iIPv4CashPurge ++ ;
            break ;
        case 6 :
            vCashStat.iIPv6CashCount -- ;
            if ( vCashStat.iIPv6CashCount < 0 ) {
                /* Bug */
                milterLog( LOG_CRIT, "ERROR: purgeOldIPcash: vCashStat.iIPv6CashCount=%d ", vCashStat.iIPv6CashCount ) ;
                vCashStat.iIPv4CashCount = 0 ;
            }
            if ( ! bExpire ) vCashStat.iIPv6CashPurge ++ ;
            break ;
        default :
            /* Bug */
            milterLog( LOG_CRIT, "ERROR: purgeOldIPcash: Unkown IP version [%d]", pByteTreeNode->iIPversion ) ;
            break ;
        }

        pByteTreeNode->iCashChainCount -- ;
        if ( ( pByteTreeNode->iCashChainCount <  0 )
          || ( pByteTreeNode->iCashChainCount == 0 && pByteTreeNode->pCashChainFirst != NULL )
          || ( pByteTreeNode->iCashChainCount >  0 && pByteTreeNode->pCashChainFirst == NULL ) ) {
            /* Bug */
            milterLog( LOG_CRIT, "ERROR: purgeOldIPcash: iIPversion=%d iOctetNumber=%d iCashChainCount=%d pCashChainFirst=%p pCashChainLast=%p",
                       pByteTreeNode->iIPversion, pByteTreeNode->iOctetNumber, pByteTreeNode->iCashChainCount,
                       pByteTreeNode->pCashChainFirst, pByteTreeNode->pCashChainLast ) ;
            if ( pByteTreeNode->pCashChainFirst == NULL ) {
                pByteTreeNode->iCashChainCount = 0 ;
            } else if ( pByteTreeNode->pCashChainFirst == pByteTreeNode->pCashChainLast ) {
                pByteTreeNode->iCashChainCount = 1 ;
            } else {
                pByteTreeNode->iCashChainCount = 2 ;
            }
        }

        /* Remove ByteTreeNode which has no IP cash and no lower node */

        for ( iNodeLevel = pByteTreeNode->iOctetNumber ; iNodeLevel > 1 ; iNodeLevel -- ) {

            struct  ByteTreeNode    *pUpperByteTreeNode ;

            if ( pByteTreeNode == NULL ) {
                /* Bug */
                milterLog( LOG_CRIT, "ERROR: purgeOldIPcash: iOctetNumber=[%d] pByteTreeNode is NULL]", iNodeLevel ) ;
                break ;
            }

            pUpperByteTreeNode = pByteTreeNode->pUpperNode ;

	        if ( pByteTreeNode->iLowerNodeCount == 0 && pByteTreeNode->iCashChainCount == 0 ) {
	            /* Remove ByteTreeNode if no IPcash and lower than second level */
	            deleteByteTreeNode( pByteTreeNode ) ;
	        } else {
	            break ;
	        }

            pByteTreeNode = pUpperByteTreeNode ;

            if ( iNodeLevel > 1 && pUpperByteTreeNode == NULL ) {
                /* Bug */
                milterLog( LOG_CRIT, "ERROR: purgeOldIPcash: iOctetNumber=[%d] pUpperNode is NULL]", iNodeLevel ) ;
                break ;
            }

        }

    }

    milterLog( LOG_DEBUG, "purgeOldIPcash: Purge cash: CashMax=%lu, CashSize=%lu->%lu, iIPv4CashPurge=%u->%u, IPv4NodeCount=%d->%d, IPv4CashCount=%d->%d, iIPv6CashPurge=%u->%u, IPv6NodeCount=%d->%d, IPv6CashCount=%d->%d",
                iCashMax, iCurrentCashSize, iCashSize,
                iCurrentIPv4CashPurge, vCashStat.iIPv4CashPurge,
                iCurrentIPv4NodeCount, vCashStat.iIPv4NodeCount,
                iCurrentIPv4CashCount, vCashStat.iIPv4CashCount,
                iCurrentIPv6CashPurge, vCashStat.iIPv6CashPurge,
                iCurrentIPv6NodeCount, vCashStat.iIPv6NodeCount,
                iCurrentIPv6CashCount, vCashStat.iIPv6CashCount ) ;

}

/**************************************************************************************************/

static struct ByteTreeNode *createByteTreeNode( struct ByteTreeNode *pParentNode, int iIPversion, int iOctetNumber )
{

    struct  ByteTreeNode    *pByteTreeNode ;
    int     i ;

    pByteTreeNode = malloc( sizeof( struct ByteTreeNode ) ) ;
    if ( pByteTreeNode == NULL ) {
        milterLog( LOG_ERR, "ERROR: createByteTreeNode: malloc" ) ;
        return NULL ;
    }
    iCashSize += sizeof( struct ByteTreeNode ) ;

    if ( iOctetNumber == 1 ) {
        if ( pParentNode != NULL ) {
            milterLog( LOG_CRIT, "ERROR: createByteTreeNode: iOctetNumber=[%d] pParentNode is not NULL", iOctetNumber ) ;
        }
    } else if ( iOctetNumber <= 8 ) {
        if ( pParentNode == NULL ) {
            milterLog( LOG_CRIT, "ERROR: createByteTreeNode: iOctetNumber=[%d] pParentNode is NULL", iOctetNumber ) ;
        }
    } else {
        milterLog( LOG_CRIT, "ERROR: createByteTreeNode: Invalid octet number [%d]", iOctetNumber ) ;
    }

    switch ( iIPversion ) {
    case 4 :
        vCashStat.iIPv4NodeCount ++ ;
        break ;
    case 6 :
        vCashStat.iIPv6NodeCount ++ ;
        break ;
    default :
        milterLog( LOG_CRIT, "ERROR: createByteTreeNode: Unkown IP version [%d]", iIPversion ) ;
        break ;
    }

    pByteTreeNode->iIPversion = iIPversion ;
    pByteTreeNode->iOctetNumber = iOctetNumber ;
    pByteTreeNode->pUpperNode = pParentNode ;

    for ( i = 0 ; i < sizeof(pByteTreeNode->pLowerNodeIndex) / sizeof(void*) ; i ++ ) {
        pByteTreeNode->pLowerNodeIndex[i] = NULL ;
    }

    pByteTreeNode->pCashChainFirst = NULL ;
    pByteTreeNode->pCashChainLast  = NULL ;

    pByteTreeNode->iLowerNodeCount = 0 ;
    pByteTreeNode->iCashChainCount = 0 ;

    return pByteTreeNode ;

}

/**************************************************************************************************/

static void deleteByteTreeNode( struct ByteTreeNode *pByteTreeNode )
{

    struct  ByteTreeNode    *pUpperNode ;
    int     i ;

    if ( pByteTreeNode->iOctetNumber < 1 || 8 < pByteTreeNode->iOctetNumber ) {
        milterLog( LOG_CRIT, "ERROR: deleteByteTreeNode: Invalid octet number [%d]", pByteTreeNode->iOctetNumber ) ;
    }

    pUpperNode = pByteTreeNode->pUpperNode ;

    if ( pUpperNode != NULL ) {
        int     iUpperNodeCount = 0 ;
        for ( i = 0 ; i < sizeof(pUpperNode->pLowerNodeIndex) / sizeof(void*) ; i ++ ) {
            if ( pUpperNode->pLowerNodeIndex[i] == pByteTreeNode ) {
                pUpperNode->pLowerNodeIndex[i] = NULL ;
                pUpperNode->iLowerNodeCount -- ;
                iUpperNodeCount ++ ;
            }
        }
        if ( iUpperNodeCount != 1 ) {
            milterLog( LOG_CRIT, "ERROR: deleteByteTreeNode: Number of match LowerNodeIndex of the upper node is [%d]", iUpperNodeCount ) ;
        }
    } else {
        /* No upper ByteTreeNode */
        if ( pByteTreeNode->iOctetNumber > 1 ) {
            milterLog( LOG_CRIT, "ERROR: deleteByteTreeNode: Octet number [%d] but upper node is [NULL]", pByteTreeNode->iOctetNumber ) ;
        }
    }

    switch ( pByteTreeNode->iIPversion ) {
    case 4 :
        vCashStat.iIPv4NodeCount -- ;
        break ;
    case 6 :
        vCashStat.iIPv6NodeCount -- ;
        break ;
    default :
        milterLog( LOG_CRIT, "ERROR: deleteByteTreeNode: Unkown IP version [%d]", pByteTreeNode->iIPversion ) ;
        break ;
    }

    free( pByteTreeNode ) ;
    iCashSize -= sizeof( struct ByteTreeNode ) ;

}

/**************************************************************************************************/

static void insertIPcash( struct IPcash *pIPcash )
{

    struct ByteTreeNode *pByteTreeNode ;

    /* Insert into Leaf chain of the ByteTreeNode */

    pByteTreeNode = pIPcash->pNode ;

    if ( pByteTreeNode->pCashChainFirst == NULL ) {
        pIPcash->pNext = NULL ;
        pByteTreeNode->pCashChainLast = pIPcash ;
    } else {
        ((struct IPcash *)(pByteTreeNode->pCashChainFirst))->pBack = pIPcash ;
        pIPcash->pNext = pByteTreeNode->pCashChainFirst ;
    }
    pIPcash->pBack = NULL ;
    pByteTreeNode->pCashChainFirst = pIPcash ;

    /* Insert into Cash chain */

    if ( pCashChainFirst == NULL ) {
        pIPcash->pNextCash = NULL ;
        pCashChainLast = pIPcash ;
    } else {
        ((struct IPcash *)pCashChainFirst)->pBackCash = pIPcash ;
        pIPcash->pNextCash = pCashChainFirst ;
    }
    pIPcash->pBackCash = NULL ;
    pCashChainFirst = pIPcash ;

}

/**************************************************************************************************/

static void removeIPcash( struct IPcash *pIPcash )
{

    struct ByteTreeNode *pByteTreeNode ;

    /* Remove from Leaf chain of the ByteTreeNode */

    pByteTreeNode = pIPcash->pNode ;

    if ( pByteTreeNode->pCashChainFirst == pIPcash && pByteTreeNode->pCashChainLast == pIPcash ) {
        /* Only one in the chain */
        pByteTreeNode->pCashChainFirst = NULL ;
        pByteTreeNode->pCashChainLast  = NULL ;
    } else if ( pByteTreeNode->pCashChainFirst == pIPcash ) {
        /* First of the chain */
        pByteTreeNode->pCashChainFirst = pIPcash->pNext ;
        ((struct IPcash *)(pByteTreeNode->pCashChainFirst))->pBack = NULL ;
    } else if ( pByteTreeNode->pCashChainLast == pIPcash ) {
        /* Last of the chain */
        pByteTreeNode->pCashChainLast = pIPcash->pBack ;
        ((struct IPcash *)(pByteTreeNode->pCashChainLast))->pNext = NULL ;
    } else {
        /* Middle of the chain */
        ((struct IPcash *)(pIPcash->pBack))->pNext = pIPcash->pNext ;
        ((struct IPcash *)(pIPcash->pNext))->pBack = pIPcash->pBack ;
    }

    /* Remove from Cash chain */

    if ( pCashChainFirst == pIPcash && pCashChainLast == pIPcash ) {
        /* Only one in the chain */
        pCashChainFirst = NULL ;
        pCashChainLast  = NULL ;
    } else if ( pCashChainFirst == pIPcash ) {
        /* First of the chain */
        pCashChainFirst = pIPcash->pNextCash ;
        ((struct IPcash *)pCashChainFirst)->pBackCash = NULL ;
    } else if ( pCashChainLast == pIPcash ) {
        /* Last of the chain */
        pCashChainLast = pIPcash->pBackCash ;
        ((struct IPcash *)pCashChainLast)->pNextCash = NULL ;
    } else {
        /* Middle of the chain */
        ((struct IPcash *)(pIPcash->pBackCash))->pNextCash = pIPcash->pNextCash ;
        ((struct IPcash *)(pIPcash->pNextCash))->pBackCash = pIPcash->pBackCash ;
    }

    /* Release memory */

    free( pIPcash ) ;
    iCashSize -= sizeof( struct IPcash ) ;

}

/**************************************************************************************************/

static bool IsMatchIPv6Prefix( const uchar *pIPv6Address, const uchar *pIPv6Prefix, int iCidr )
{

    static  uchar  bMask[65][8] =
        {
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },

        { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },

        { 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },

        { 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00 },

        { 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xF8, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFC, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 },

        { 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xF8, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00 },

        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00 },

        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },

        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8 },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE },
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
        } ;

    int     i ;
    bool    bMatch ;

    if ( iCidr <= 0 || 64 < iCidr ) {
        milterLog( LOG_WARNING, "WARNING: IsMatchIPv6Prefix: Invalid CIDR" ) ;
        return false ;
    }

    bMatch = true ;

    for ( i = 0 ; i <= 7 ; i ++ ) {
        if ( ( pIPv6Address[i] & bMask[iCidr][i] ) != pIPv6Prefix[i] ) {
            bMatch = false ;
            break ;
        }
    }

    return bMatch ;

}

/**************************************************************************************************/
