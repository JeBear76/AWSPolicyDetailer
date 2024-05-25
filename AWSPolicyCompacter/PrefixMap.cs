namespace AWSPolicyCompacter
{
    internal class PrefixMap
    {
        public PrefixMap()
        {
            prefix = "";
            service = "";
        }
        public string prefix { get; set; }
        public string service { get; set; }
    }
}