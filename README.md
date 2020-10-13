# Get-RIPEBulkIPRanges
Simple function for querying RIPE database for ip ranges. As input parameter expects file with public ip addresses (one ip address per line) to query for ip range.  Output parameter is list of ip address ranges in CIDR format.
For IP addresses/ranges manipulation the function requires Indented.Net.IP module from powershell gallery.
For quering the RIPE database there is Whois function, which connects to RIPE on port 43, send the command and parse the output.

Feel free to modify and comment.
