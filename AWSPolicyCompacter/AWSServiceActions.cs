namespace AWSPolicyCompacter
{
    public class AWSServiceActions
    {
        public AWSServiceActions()
        {
            ServiceName = "";
            Actions = new string[0];
            StringPrefix = "";
        }
        public string ServiceName { get; set; }
        public string[] Actions { get; set; }
        public string StringPrefix { get; set; }
    }
}