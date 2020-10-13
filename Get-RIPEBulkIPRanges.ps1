
Install-Module -Name Indented.Net.IP -force  -Scope CurrentUser

function Whois {
    
param (
        [Parameter(Mandatory, Position = 1, ValueFromPipeline)]
        [String]$IPAddress,

        [Parameter(Position = 2)]
        [String]$server
    )


    
    if ($null -eq $server -or $server -eq '') {$server ="whois.ripe.net" }
    $port = 43
    #make connection
    $socket = new-object Net.Sockets.TcpClient
    $socket.Connect($server, $port)

        if($socket.Connected){
            Write-Host "Connected! $server"
            $stream = $socket.GetStream()
    
            $writer = new-object System.IO.StreamWriter $stream
            #syntax specific to RIR
            $line ="-r --resource $ipaddress"
                $writer.WriteLine($line) 
                $writer.Flush() 
                Start-Sleep -m 5
            #read response
                    $buffer = new-object System.Byte[] 1024
                    $encoding = new-object System.Text.AsciiEncoding
                    $stream.ReadTimeout = 1000
           
                    do{ 
                        try{ 
                            $read = $stream.Read($buffer, 0, 1024)
               
                            if($read -gt 0){ 
                                $foundMore = $true
                                $outputBuffer += ($encoding.GetString($buffer, 0, $read))
                            } 
                        }catch{ 
                            $foundMore = $false 
                            $read = 0
                        }        
                    }while($read -gt 0)
            #display results
          #  $outputBuffer
          #close Socket        
    $socket.Close()
    $outputBuffer = $outputBuffer -split "`n"
    $riperange = $outputBuffer| select-string -pattern  'inetnum'
    if ($riperange.ToString().contains("inetnum")) {
        
        $addr =  $riperange.ToString().Split(':')
        return $addr[1].Trim()
    }
    else {

            Return "oops"
               
    }
   
}else{
    Write-Host "Unable to Connect! Check your internet connection or firewall port 43 !"
}

}

function Get-RIPEBulkIPRanges {
    <#
    .SYNOPSIS
        Convert public ip addresses from input to public ip range from RIPE.
    .DESCRIPTION
        Simple function for querying RIPE database for ip ranges. As input parameter expects file with public ip addresses (one ip address per line) to query for ip range. Output parameter is list of ip address ranges in CIDR format.
    .INPUTS
        File path to file containing the ip addresses for checking to RIPE
    .EXAMPLE
        Get-RIPEBulkIPRanges -file "C:\Temp\ip.txt"
    #>

    [CmdletBinding()]
    param (
        # path to file containg the public ip addreses to check for network formated one ip address per single line.        
        [Parameter(Mandatory, Position = 1)]
        [System.IO.FileInfo]$file

    )


$ipsumlist = [System.Collections.ArrayList]@()
$ips = Get-Content $file

    foreach ($ip in $ips) {
    $ip
        # Contact RIPE for Address Range 
        $whoisrange = Whois $ip
        $Range=  $whoisrange.split('-')
        $net = ConvertTo-Subnet -Start $Range[0].trim() -End $Range[1].trim()
        #Converting Netowrk into CIDR
        $mrcidr  = $net.NetworkAddress.IPAddressToString + "/" + $net.masklength
        #Checking the presence of the network into arraylist to avoid duplicates   
            if ( $ipsumlist.Count -eq 0 )  {
                $ipsumlist.Add($mrcidr)
            }
             else {
                if (!($ipsumlist.Contains($mrcidr))) {

                    $added = $false
                    foreach ($iplisted in $ipsumlist) {
                    #Checkinfg if the network is already part of network
                    if (Test-SubnetMember -SubjectIPAddress $iplisted -ObjectIPAddress $mrcidr) {
                        $ipsumlist.Remove($iplisted)
                        
                        If (!($added)) { 
                            $ipsumlist.Add($mrcidr) > $null
                            $added = $true
                        }
                    }
                }
                if (!($added)) {$ipsumlist.Add($mrcidr) > $null}
 
                }   
             }
            }

            return $ipsumlist
        }

