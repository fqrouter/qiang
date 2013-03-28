#destination

To run effective probe, we can send from different sources to different destinations, in the hope we will pass
through different routers with GFW device attached. When sending from China, we would
want to send to different countries. When sending from outside, we would want to send to ip of different carriers.
Scripts in this directory provides different strategy to get ip of different types.

There are four ways to get a list of random ip

* ./by_carrier.py CHINANET which use whoise database to get ip range directly
* ./by_carrier.py CHINANET asn | ./by_asn @stdin use whoise database to find asn then use bgp.he.net to find ip range for that as.
* ./by_country.py CN which use apnic allocation data to get ip range directly
* ./by_country.py CN asn | ./by_asn @stdin use apnic allocation data to find asn then use bgp.he.net to find ip range for that as.
