using Amazon.Auth.AccessControlPolicy;

namespace AWSPolicyCompacter
{
    internal class PolicyWorker
    {
        static readonly string[] ReadonlyDescriptors = ["Read", "View", "Describe", "List", "Get"];

        private readonly Policy _policy;
        private readonly Mapper _mapper;
        private Policy _detailedPolicy;

        public PolicyWorker(Policy policy, Mapper mapper)
        {
            _policy = policy;
            _mapper = mapper;
        }

        public Policy GetDetailedPolicy(string policyName)
        {
            _detailedPolicy = GetBasePolicy(policyName);

            var detailActions = new HashSet<ActionIdentifier>();
            var removeActions = new HashSet<ActionIdentifier>();
            // Iterate through each statement in the policy
            foreach (var statement in _policy.Statements)
            {
                // Iterate through each action in the statement
                foreach (var action in statement.Actions)
                {
                    if (action.ActionName.EndsWith("*"))
                    {
                        var expandedActions = GetPermissionSet(action, _mapper);
                        
                        removeActions.Add(action);

                        detailActions.UnionWith(expandedActions);
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
                    _detailedPolicy.Statements[0].Actions = _detailedPolicy.Statements[0].Actions
                                                                .Union(detailActions.ToList())
                                                                .ToList();
                }
                else
                {
                    foreach (var action in removeActions)
                    {
                        statement.Actions.Remove(action);
                    }
                    statement.Actions = detailActions.ToList();
                    _detailedPolicy.Statements.Add(statement);
                }
                removeActions.Clear();
                detailActions.Clear();
            }
            return _detailedPolicy;
        }

        private static HashSet<ActionIdentifier> GetPermissionSet(ActionIdentifier action, Mapper mapper)
        {
            HashSet<ActionIdentifier> expandedActions;
            var (services, actions) = mapper.GetActionsSubset(action.ActionName);

            expandedActions = BuildDetailedActions(services, actions);
            return expandedActions;
        }

        internal Policy TightenPolicy(string policyName)
        {
            var tightPolicy = GetDetailedPolicy(policyName);

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

            if (tightPolicy.Statements.Count == 0)
                return null!;

            return tightPolicy;
        }

        private static HashSet<ActionIdentifier> BuildDetailedActions(IEnumerable<ServicePrefixMap> services, IEnumerable<string> actions)
        {
            HashSet<string> actionNames = new HashSet<string>();
            foreach (var service in services)
            {
                foreach (var actionName in actions)
                {
                    actionNames.Add($"{service.prefix}:{actionName}");
                }
            }
            return actionNames.Select(a => new ActionIdentifier(a)).ToHashSet();
        }

        private static bool isReadonlyAction(ActionIdentifier action)
        {
            foreach (var descriptor in ReadonlyDescriptors)
            {
                if (action.ActionName.Contains($":{descriptor}", StringComparison.CurrentCultureIgnoreCase))
                    return true;
            }
            return false;
        }

        private static Policy GetBasePolicy(string policyName)
        {
            return new Policy
            {
                Id = policyName,
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
        }

        public static Policy CombinePolicies(IEnumerable<Policy> policies, Mapper mapper, string policyName)
        {
            var combinedPolicy = GetBasePolicy(policyName);
            var giantActionList = new HashSet<ActionIdentifier>();

            foreach (var policy in policies)
            {
                foreach (var statement in policy.Statements)
                {
                    if (statement.Resources.Count == 1
                        && statement.Resources[0].Id == "*"
                        && statement.Conditions.Count == 0)
                    {
                        giantActionList.UnionWith(statement.Actions);
                        continue;
                    }
                    combinedPolicy.Statements.Add(statement);
                }
            }

            // Set the actions of the first statement in the giant policy to the giant action list
            var fullAccesPermissions = giantActionList.Where(a => a.ActionName.EndsWith("*")).ToHashSet();
            fullAccesPermissions = fullAccesPermissions.GroupBy(p => p.ActionName.Substring(0, p.ActionName.IndexOf(":")))
                .SelectMany(g => {
                    if (g.Any(a => a.ActionName == $"{g.Key}:*"))
                        return new List<ActionIdentifier>() { new ActionIdentifier($"{g.Key}:*") };
                    else
                        return g.GroupBy(sg => sg.ActionName.Substring(sg.ActionName.IndexOf("*")))
                                    .SelectMany(saa => {
                                        if (saa.Any(a => a.ActionName == $"{saa.Key}*"))
                                            return new List<ActionIdentifier>() { new ActionIdentifier($"{saa.Key}*") };
                                        else
                                            return saa.ToList();
                                    });
                }).ToHashSet();
            
            foreach (var fullAction in fullAccesPermissions)
            {
                var permissionSet = GetPermissionSet(fullAction, mapper);

                giantActionList.RemoveWhere(a => permissionSet.Any(p => p.ActionName == a.ActionName));
                
            }            

            combinedPolicy.Statements[0].Actions = giantActionList.Distinct(new ActionIdentifierComparer()).OrderBy(o => o.ActionName).ToList();

            return combinedPolicy;
        }
    }

    internal class ActionIdentifierComparer : IEqualityComparer<ActionIdentifier>
    {
        public bool Equals(ActionIdentifier? actionX, ActionIdentifier? actionY)
        {

            if (actionX is null)
                return false;

            if (actionY is null)
                return false;
            return actionX.ActionName == actionY.ActionName;
        }

        public int GetHashCode(ActionIdentifier obj)
        {
            return obj.ActionName.GetHashCode();
        }
    }
}
