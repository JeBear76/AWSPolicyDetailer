using Amazon.Auth.AccessControlPolicy;
using Newtonsoft.Json.Linq;
using System.Text.RegularExpressions;

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
            }


            Console.WriteLine($"{jsonFiles.Length} JSON files have been read and deserialized successfully.");

            string json = File.ReadAllText(@".\policies.json");

            var policyActionMapping = JObject.Parse(json);

            if (policyActionMapping is null)
            {
                Console.WriteLine("Failed to deserialize JSON Policy Action Mapping file.");
                return;
            }
            var serviceMap = policyActionMapping.Properties().First(v => v.Name.Equals("serviceMap", StringComparison.CurrentCultureIgnoreCase)).Value as JObject;

            var serviceActionMap = new List<AWSServiceActions>();

            foreach (var service in serviceMap.Properties())
            {
                serviceActionMap.Add(new AWSServiceActions
                {
                    ServiceName = service.Name,
                    Actions = service.Value["Actions"].ToObject<string[]>(),
                    StringPrefix = service.Value["StringPrefix"].ToString()
                });
            }

            List<PrefixMap> prefixMap = new List<PrefixMap>();
            foreach (Match match in Regex.Matches(json, @"\s+""(?<ServiceName>[\w\s\-\(\)]+)"":\s\{\s+""StringPrefix"":\W""(?<ServicePrefix>[\w\s\-]+)""", RegexOptions.ExplicitCapture))
            {
                prefixMap.Add(new PrefixMap() { service = match.Groups["ServiceName"].Value.Replace(" ", ""), prefix = match.Groups["ServicePrefix"].Value });
            }


            Policy giantPolicy = new Policy
            {
                Id = "CaissaDeveloperDEVPolicy",
                Version = "2012-10-17",
                Statements = new List<Statement>()
                {
                    new Statement(Statement.StatementEffect.Allow)
                    {
                        Resources = new List<Resource>
                        {
                            new Resource("*"),
                        },
                    }
                },

            };

            foreach (var policy in policies)
            {
                foreach (var statement in policy.Statements)
                {
                    if (statement.Resources.Count == 1
                        && statement.Resources[0].Id == "*"
                        && statement.Conditions.Count == 0)
                    {
                        foreach (var action in statement.Actions)
                        {
                            if (action.ActionName.EndsWith(":*"))
                            {
                                Console.WriteLine(action.ActionName);
                                var services = prefixMap.Where(p => p.prefix == action.ActionName[0..^2]);
                                if (services.Count() == 0)
                                {
                                    Console.WriteLine("-------------- No Service? ------------");
                                    continue;
                                }
                                foreach (var service in services)
                                {
                                    Console.WriteLine(service.service);
                                }
                                IEnumerable<string> actions = serviceActionMap.Where(s => s.StringPrefix == action.ActionName[0..^2]).SelectMany(s => s.Actions).Distinct();
                                if (actions is null)
                                {
                                    Console.WriteLine("-------------- No Actions? ------------");
                                    continue;
                                }
                                foreach (var actionName in actions)
                                {
                                    Console.WriteLine($"\t{action.ActionName[0..^2]}:{actionName}");
                                }
                            }

                        }
                    }
                }
            }

            Console.WriteLine("JSON Policy Action Mapping file has been read and deserialized successfully.");

        }

    }
}
