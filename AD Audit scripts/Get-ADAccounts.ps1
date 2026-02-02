Number of User Accounts 
(get-aduser –filter ).count 

Number of Enabled User Accounts 
(get-aduser -filter *|where {$_.enabled -eq "True"}).count

Number of Disabled User Accounts 
(get-aduser -filter *|where {$_.enabled -ne "False"}).count
