using Newtonsoft.Json.Linq;
using System.Text.RegularExpressions;

namespace AWSPolicyCompacter
{
    internal class Mapper
    {
        readonly List<ServicePrefixMap> _prefixMap;
        readonly List<AWSServiceActions> _serviceActions;
        
        public Mapper()
        {
            // Read the policy action mapping JSON file
            string json = File.ReadAllText(@".\policies.json");

            // Parse the policy action mapping JSON
            var policyActionMapping = JObject.Parse(json);

            // Check if the policy action mapping JSON was deserialized successfully
            if (policyActionMapping is null)
            {
                Console.WriteLine("Failed to deserialize JSON Policy Action Mapping file.");
                return;
            }

            // Get the service map from the policy action mapping JSON
            var serviceMap = policyActionMapping.Properties().First(v => v.Name.Equals("serviceMap", StringComparison.CurrentCultureIgnoreCase)).Value as JObject;

            if (serviceMap is null)
            {
                Console.WriteLine("Failed to extract service map.");
                return;
            }

            // Create a list to store the service action mappings
            _serviceActions = new List<AWSServiceActions>();

            // Iterate through each service in the service map
            foreach (var service in serviceMap.Properties())
            {
                // Create a new AWSServiceActions object and populate its properties
                _serviceActions.Add(new AWSServiceActions
                {
                    ServiceName = service.Name,
                    Actions = service.Value["Actions"]!.ToObject<string[]>()!,
                    StringPrefix = service.Value["StringPrefix"]!.ToString()
                });
            }

            // Create a list to store the prefix mappings
            _prefixMap = new List<ServicePrefixMap>();

            // Use regular expressions to extract prefix mappings from the policy action mapping JSON
            foreach (Match match in Regex.Matches(json, @"\s+""(?<ServiceName>[\w\s\-\(\)]+)"":\s\{\s+""StringPrefix"":\W""(?<ServicePrefix>[\w\s\-]+)""", RegexOptions.ExplicitCapture))
            {
                // Create a new PrefixMap object and populate its properties
                _prefixMap.Add(new ServicePrefixMap() { service = match.Groups["ServiceName"].Value.Replace(" ", ""), prefix = match.Groups["ServicePrefix"].Value });
            }
        }

        internal (IEnumerable<ServicePrefixMap>, IEnumerable<string>) GetActions(string policyAction)
        {
            var servicePrefix = policyAction[0..^2];

            // Find the services that match the action prefix
            var services = _prefixMap.Where(p => p.prefix == servicePrefix);

            // Check if any services were found
            if (services.Count() == 0)
            {
                Console.WriteLine($"{policyAction}-------------- No Service? ------------");
                return (null!,null!);
            }

            // Print the services
            foreach (var service in services)
            {
                Console.WriteLine(service.service);
            }

            // Get the actions for the matching service prefixes
            IEnumerable<string> actions = _serviceActions.Where(s => s.StringPrefix.Equals(servicePrefix, StringComparison.CurrentCultureIgnoreCase)).SelectMany(s => s.Actions).Distinct();

            // Check if any actions were found
            if (actions is null)
            {
                Console.WriteLine($"{policyAction}-------------- No Actions? ------------");
                return (services, null!);
            }

            return (services, actions);
        }

        internal (IEnumerable<ServicePrefixMap>, IEnumerable<string>) GetDescriptorActions(string policyAction)
        {
            var servicePrefix = policyAction.Substring(0, policyAction.IndexOf(':'));

            // Find the service that matches the action prefix
            var services = _prefixMap.Where(p => p.prefix == servicePrefix);

            // Check if the service was found
            if (services is null)
            {
                Console.WriteLine($"{policyAction}-------------- No Service? ------------");
                return (null!, null!);
            }

            // Print the services
            foreach (var service in services)
            {
                Console.WriteLine(service.service);
            }

            // Get the actions for the matching service prefix and action suffix
            IEnumerable<string> actions = _serviceActions.Where(s => services.Any(p => p.prefix.Equals(s.StringPrefix, StringComparison.CurrentCultureIgnoreCase))).SelectMany(s => s.Actions).Where(a => a.StartsWith(policyAction.Substring(policyAction.IndexOf(':') + 1)[0..^1], StringComparison.CurrentCultureIgnoreCase));

            // Check if any actions were found
            if (actions is null || !actions.Any())
            {
                Console.WriteLine($"{policyAction}-------------- No Actions? ------------");
                return (services, null!);
            }

            return (services, actions);
        }
    }
}
