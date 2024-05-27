using Amazon.Auth.AccessControlPolicy;

namespace AWSPolicyCompacter
{
    internal class PolicyWorker
    {
        static readonly string[] ReadonlyDescriptors = ["Read","View","Describe","List","Get"];

        private readonly Policy _policy;
        private readonly Mapper _mapper;
        private Policy _detailedPolicy;

        public PolicyWorker(Policy policy, Mapper mapper)
        {
            _policy = policy;
            _mapper = mapper;
        }

        public Policy GetDetailedPolicy()
        {
            _detailedPolicy = new Policy
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

            var giantActionList = new HashSet<ActionIdentifier>();
            var detailActions = new HashSet<ActionIdentifier>();
            var removeActions = new HashSet<ActionIdentifier>();
            // Iterate through each statement in the policy
            foreach (var statement in _policy.Statements)
            {
                // Iterate through each action in the statement
                foreach (var action in statement.Actions)
                {
                    // Check if the action ends with ":*"
                    if (action.ActionName.EndsWith(":*"))
                    {
                        var (services, actions) = _mapper.GetActions(action.ActionName);

                        removeActions.Add(action);

                        BuildDetailedActions(detailActions, services, actions);

                    }
                    // Check if the action ends with "*"
                    else if (action.ActionName.EndsWith("*"))
                    {
                        var (services, actions) = _mapper.GetDescriptorActions(action.ActionName);

                        removeActions.Add(action);
                        
                        BuildDetailedActions(detailActions, services, actions);
                    }
                    else
                    {
                        detailActions.Add(new ActionIdentifier(action.ActionName));
                    }
                }
                // Check if the statement allows all resources and has no conditions
                if (statement.Resources.Count == 1
                    && statement.Resources[0].Id == "*"
                    && statement.Conditions.Count == 0)
                {
                    giantActionList.UnionWith(detailActions);
                }
                else
                {

                    statement.Actions.Clear();
                    foreach (var action in detailActions)
                    {
                        statement.Actions.Add(action);
                    }
                    // Add the statement to the giant policy
                    _detailedPolicy.Statements.Add(statement);
                }
                removeActions.Clear();
                detailActions.Clear();

            }

            return _detailedPolicy;
        }

        internal Policy TightenPolicy()
        {
            if(_detailedPolicy is null)
            {
                GetDetailedPolicy();
            }

            var tightPolicy = Policy.FromJson(_detailedPolicy!.ToJson());

            var removeActions = new HashSet<ActionIdentifier>();
            var RemoveStatement = new HashSet<Statement>();

            foreach (var statement in _detailedPolicy.Statements)
            {
                foreach (var action in statement.Actions)
                {
                    if (!isReadonlyAction(action))
                        removeActions.Add(action);
                }
                foreach (var action in removeActions)
                {
                    statement.Actions.Remove(action);
                }
                if (statement.Actions.Count == 0)
                {
                    RemoveStatement.Add(statement);
                }
                removeActions.Clear();
            }

            foreach (var statement in RemoveStatement)
            {
                tightPolicy.Statements.Remove(statement);
            }
            RemoveStatement.Clear();

            return tightPolicy;
        }

        private static void BuildDetailedActions(HashSet<ActionIdentifier> detailActions, IEnumerable<ServicePrefixMap> services, IEnumerable<string> actions)
        {
            foreach (var service in services)
                foreach (var actionName in actions)
                {
                    //Console.WriteLine($"\t{service.prefix}:{actionName}");
                    detailActions.Add(new ActionIdentifier($"{service.prefix}:{actionName}"));
                }
        }

        private static bool isReadonlyAction(ActionIdentifier action)
        {
            foreach (var descriptor in ReadonlyDescriptors)
            {
                if (action.ActionName.StartsWith(descriptor))
                    return true;
            }
            return false;
        }
    }
}
