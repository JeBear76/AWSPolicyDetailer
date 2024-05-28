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
            File.WriteAllText(@".\adminPolicy.json", PolicyWorker.CombinePolicies(policies, mapper, "CaissaCorrectedSalesAdminPolicy").ToJson(true));

            var detailedPolicies = new List<Policy>();
            var tightPolicies = new List<Policy>();

            foreach (var policy in policies)
            {
                var worker = new PolicyWorker(policy, mapper);
                detailedPolicies.Add(worker.GetDetailedPolicy("CaissaCorrectedSalesAdminPolicy"));
                var tightPolicy = worker.TightenPolicy("CaissaCorrectedSalesReadOnlyPolicy");
                if (tightPolicy is not null)
                    tightPolicies.Add(tightPolicy);
            }



            // Write the giant policy to a JSON file

            File.WriteAllText(@".\adminLongPolicy.json", PolicyWorker.CombinePolicies(detailedPolicies, mapper, "CaissaCorrectedSalesAdminPolicy").ToJson(true));

            File.WriteAllText(@".\readonlyPolicy.json", PolicyWorker.CombinePolicies(tightPolicies, mapper, "CaissaCorrectedSalesReadOnlyPolicy").ToJson(true));
        }
    }
}
