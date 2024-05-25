# AWS Policy Compacter / Detailer

The purpose of this app is to detail the permissions of an AWS IAM policy.  
It will take a policy in JSON format and output a more detailed version of the policy.  
This is useful for understanding the permissions of a policy, especially when the policy is large and complex.  

It will then generate a single policy file to associate with a specific role.  

Ultimately, I want to use it to be able to remove unwanted policies to align with PoLP while still allowing the role in question to function. 



