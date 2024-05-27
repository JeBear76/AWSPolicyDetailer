namespace AWSPolicyCompacter
{
    internal class ServicePrefixMap
    {
        public ServicePrefixMap()
        {
            prefix = "";
            service = "";
        }
        public string prefix { get; set; }
        public string service { get; set; }
    }
}