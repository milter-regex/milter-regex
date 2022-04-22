milter-regex 3.0   April 23th, 2022  

New feature: GeoIP  

(1) Everything about GeoIP processing is in the milter-regex source codes.  
GeoIP is implemented without MaxMind Inc.'s libraries or other GeoIP libraries.  
No dependency on the libgeoip.  

(2) Use the RIR ( Regianl Internet Registry ) IP address allocation lists for GeoIP data.  
Get country code by looking at the IP address allocation lists of the RIR.  
Those lists are converted from ASCII format to binary format by using  
the standalone utility program included in the milter-regex package.  

(3) Adding new keyword 'country' and some settings keywords for GeoIP.
