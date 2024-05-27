using Amazon.Auth.AccessControlPolicy;

namespace AWSPolicyCompacter
{
    class Program
    {
        static void Main(string[] args)
        {
            // Ask the user for a path
            Console.WriteLine("Enter the path to the JSON files (Default: ./Policies):");
            string path = Console.ReadLine();

            // Set the default path if no path is provided
            if (string.IsNullOrEmpty(path))
            {
                path = "./Policies";
            }

            // Read all the JSON files in the path
            string[] jsonFiles = Directory.GetFiles(path, "*.json");

            // Array to store the AWSPolicy objects
            Policy[] policies = new Policy[jsonFiles.Length];

            // Deserialize each JSON file into an AWSPolicy object
            for (int i = 0; i < jsonFiles.Length; i++)
            {
                string jsonPolicy = File.ReadAllText(jsonFiles[i]);
                policies[i] = Policy.FromJson(jsonPolicy);
                for (int j = 0; j < policies[i].Statements.Count; j++)
                {
                    policies[i].Statements[j].Id = $"{Path.GetFileName(jsonFiles[i][0..^4])}{j}";
                }
            }

            Mapper mapper = new Mapper();

            // Create a new Policy object for the giant policy
            Policy giantPolicy = new Policy
            {
                Id = "CaissaCorrectedSalesAdminPolicy",
                Version = "2012-10-17",
                Statements = new List<Statement>()
                    {
                        // Create a new Statement object for the generic allowed actions
                        new Statement(Statement.StatementEffect.Allow)
                        {
                            Id = "GenericAllowedActions",
                            Resources = new List<Resource>
                            {
                                new Resource("*"),
                            },
                        }
                    },

            };



            var detailedPolicies = new List<Policy>();
            var tightPolicies = new List<Policy>();
            // Iterate through each policy
            foreach (var policy in policies)
            {
                var worker = new PolicyWorker(policy, mapper);
                detailedPolicies.Add(worker.GetDetailedPolicy());
                tightPolicies.Add(worker.TightenPolicy());
            }

            // Create a HashSet to store the giant action list
            var giantActionList = new HashSet<ActionIdentifier>();

            // Set the actions of the first statement in the giant policy to the giant action list
            giantPolicy.Statements[0].Actions = giantActionList.ToList();

            // Write the giant policy to a JSON file
            File.WriteAllText(@".\adminPolicy.json", giantPolicy.ToJson(true));
            

            File.WriteAllText(@".\readonlyPolicy.json", giantPolicy.ToJson(true));
        }
    }
}
