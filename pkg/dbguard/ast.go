package dbguard

import (
	"fmt"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// InspectionResult holds the outcome of inspecting an SQL AST for security policy violations.
type InspectionResult struct {
	HasDDL                    bool
	DDLType                   string
	HasPrivilegeEscalation    bool
	PrivilegeType             string
	HasUnconstrainedMutation  bool
	UnconstrainedMutationType string
	StatementCount            int
	HasSelect                 bool
	NeedsLimitCap             bool
	Statements                []string
}

// Parse parses an SQL string into a PostgreSQL AST.
func Parse(sql string) (*pg_query.ParseResult, error) {
	return pg_query.Parse(sql)
}

// Inspect examines the parsed AST tree and checks for DDL, privilege escalation, and unconstrained mutations.
func Inspect(tree *pg_query.ParseResult) (*InspectionResult, error) {
	if tree == nil || len(tree.Stmts) == 0 {
		return &InspectionResult{}, nil
	}

	result := &InspectionResult{
		StatementCount: len(tree.Stmts),
	}

	for _, rawStmt := range tree.Stmts {
		if rawStmt == nil || rawStmt.Stmt == nil {
			continue
		}
		node := rawStmt.Stmt
		inspectNode(node, result)
	}

	return result, nil
}

// inspectNode recursively inspects a node and its CTEs / subqueries for security violations.
func inspectNode(node *pg_query.Node, res *InspectionResult) {
	if node == nil {
		return
	}

	// 1. Destructive DDL Detection - Drops
	if drop := node.GetDropStmt(); drop != nil {
		res.HasDDL = true
		res.DDLType = fmt.Sprintf("DROP %v", drop.RemoveType)
		return
	}
	if node.GetDropdbStmt() != nil {
		res.HasDDL = true
		res.DDLType = "DROP DATABASE"
		return
	}
	if node.GetDropRoleStmt() != nil {
		res.HasDDL = true
		res.DDLType = "DROP ROLE"
		return
	}
	if node.GetDropTableSpaceStmt() != nil {
		res.HasDDL = true
		res.DDLType = "DROP TABLESPACE"
		return
	}
	if node.GetDropUserMappingStmt() != nil {
		res.HasDDL = true
		res.DDLType = "DROP USER MAPPING"
		return
	}
	if node.GetDropOwnedStmt() != nil {
		res.HasDDL = true
		res.DDLType = "DROP OWNED"
		return
	}
	if node.GetDropSubscriptionStmt() != nil {
		res.HasDDL = true
		res.DDLType = "DROP SUBSCRIPTION"
		return
	}

	// 2. Destructive DDL Detection - Truncate and Rename
	if node.GetTruncateStmt() != nil {
		res.HasDDL = true
		res.DDLType = "TRUNCATE"
		return
	}
	if node.GetRenameStmt() != nil {
		res.HasDDL = true
		res.DDLType = "RENAME"
		return
	}

	// 3. Destructive DDL Detection - Alters
	if node.GetAlterTableStmt() != nil {
		res.HasDDL = true
		res.DDLType = "ALTER TABLE"
		return
	}
	if node.GetAlterDomainStmt() != nil {
		res.HasDDL = true
		res.DDLType = "ALTER DOMAIN"
		return
	}
	if node.GetAlterFunctionStmt() != nil {
		res.HasDDL = true
		res.DDLType = "ALTER FUNCTION"
		return
	}
	if node.GetAlterPolicyStmt() != nil {
		res.HasDDL = true
		res.DDLType = "ALTER POLICY"
		return
	}
	if node.GetAlterSeqStmt() != nil {
		res.HasDDL = true
		res.DDLType = "ALTER SEQUENCE"
		return
	}
	if node.GetAlterDatabaseStmt() != nil || node.GetAlterDatabaseSetStmt() != nil || node.GetAlterDatabaseRefreshCollStmt() != nil {
		res.HasDDL = true
		res.DDLType = "ALTER DATABASE"
		return
	}
	if node.GetAlterDefaultPrivilegesStmt() != nil {
		res.HasDDL = true
		res.DDLType = "ALTER DEFAULT PRIVILEGES"
		return
	}
	if node.GetAlterTableSpaceOptionsStmt() != nil || node.GetAlterTableMoveAllStmt() != nil {
		res.HasDDL = true
		res.DDLType = "ALTER TABLESPACE"
		return
	}
	if node.GetAlterExtensionStmt() != nil || node.GetAlterExtensionContentsStmt() != nil {
		res.HasDDL = true
		res.DDLType = "ALTER EXTENSION"
		return
	}
	if node.GetAlterFdwStmt() != nil || node.GetAlterForeignServerStmt() != nil || node.GetAlterUserMappingStmt() != nil {
		res.HasDDL = true
		res.DDLType = "ALTER FDW/SERVER"
		return
	}
	if node.GetAlterSystemStmt() != nil {
		res.HasDDL = true
		res.DDLType = "ALTER SYSTEM"
		return
	}
	if node.GetAlterTypeStmt() != nil || node.GetAlterEnumStmt() != nil {
		res.HasDDL = true
		res.DDLType = "ALTER TYPE"
		return
	}

	// 4. Privilege Escalation & Role Alteration
	if node.GetGrantStmt() != nil {
		res.HasPrivilegeEscalation = true
		res.PrivilegeType = "GRANT"
		return
	}
	if node.GetGrantRoleStmt() != nil {
		res.HasPrivilegeEscalation = true
		res.PrivilegeType = "GRANT ROLE"
		return
	}
	if node.GetCreateRoleStmt() != nil {
		res.HasPrivilegeEscalation = true
		res.PrivilegeType = "CREATE ROLE/USER"
		return
	}
	if node.GetAlterRoleStmt() != nil || node.GetAlterRoleSetStmt() != nil {
		res.HasPrivilegeEscalation = true
		res.PrivilegeType = "ALTER ROLE"
		return
	}

	// 5. Destructive DDL Detection - Creates (schema, tables, etc.)
	if node.GetCreateStmt() != nil || node.GetCreateTableAsStmt() != nil {
		res.HasDDL = true
		res.DDLType = "CREATE TABLE"
		return
	}
	if node.GetCreateSchemaStmt() != nil {
		res.HasDDL = true
		res.DDLType = "CREATE SCHEMA"
		return
	}
	if node.GetCreatedbStmt() != nil {
		res.HasDDL = true
		res.DDLType = "CREATE DATABASE"
		return
	}
	if node.GetCreateExtensionStmt() != nil {
		res.HasDDL = true
		res.DDLType = "CREATE EXTENSION"
		return
	}

	// 6. Unconstrained Mutation Detection
	if update := node.GetUpdateStmt(); update != nil {
		if update.WhereClause == nil {
			res.HasUnconstrainedMutation = true
			rel := "relation"
			if update.Relation != nil && update.Relation.Relname != "" {
				rel = update.Relation.Relname
			}
			res.UnconstrainedMutationType = fmt.Sprintf("UPDATE %s without WHERE", rel)
		}
		if update.WithClause != nil {
			inspectWithClause(update.WithClause, res)
		}
		return
	}

	if del := node.GetDeleteStmt(); del != nil {
		if del.WhereClause == nil {
			res.HasUnconstrainedMutation = true
			rel := "relation"
			if del.Relation != nil && del.Relation.Relname != "" {
				rel = del.Relation.Relname
			}
			res.UnconstrainedMutationType = fmt.Sprintf("DELETE FROM %s without WHERE", rel)
		}
		if del.WithClause != nil {
			inspectWithClause(del.WithClause, res)
		}
		return
	}

	// 7. Select Statement Inspection
	if sel := node.GetSelectStmt(); sel != nil {
		res.HasSelect = true
		if sel.LimitCount == nil {
			res.NeedsLimitCap = true
		}
		if sel.WithClause != nil {
			inspectWithClause(sel.WithClause, res)
		}
		return
	}
}

// inspectWithClause inspects Common Table Expressions (CTEs) for nested mutations.
func inspectWithClause(with *pg_query.WithClause, res *InspectionResult) {
	if with == nil {
		return
	}
	for _, cteNode := range with.Ctes {
		if cteNode == nil {
			continue
		}
		cte := cteNode.GetCommonTableExpr()
		if cte != nil && cte.Ctequery != nil {
			inspectNode(cte.Ctequery, res)
		}
	}
}

// EnforceLimit rewrites unbounded SELECT statements in the AST to cap rows at maxLimit.
// If a SELECT already has a LIMIT that is <= maxLimit, it is preserved.
// If it has a LIMIT > maxLimit, it is capped at maxLimit.
// Returns the rewritten SQL string, a boolean indicating if changes were made, and any deparse error.
func EnforceLimit(tree *pg_query.ParseResult, maxLimit int64) (string, bool, error) {
	if tree == nil || len(tree.Stmts) == 0 || maxLimit <= 0 {
		return "", false, nil
	}

	modified := false

	for _, rawStmt := range tree.Stmts {
		if rawStmt == nil || rawStmt.Stmt == nil {
			continue
		}
		sel := rawStmt.Stmt.GetSelectStmt()
		if sel == nil {
			continue
		}

		if sel.LimitCount == nil {
			// Unbounded query: inject LIMIT maxLimit
			sel.LimitOption = pg_query.LimitOption_LIMIT_OPTION_COUNT
			sel.LimitCount = &pg_query.Node{
				Node: &pg_query.Node_AConst{
					AConst: &pg_query.A_Const{
						Val: &pg_query.A_Const_Ival{
							Ival: &pg_query.Integer{
								Ival: int32(maxLimit),
							},
						},
					},
				},
			}
			modified = true
		} else {
			// Query already has a limit; check if it exceeds maxLimit
			aConst := sel.LimitCount.GetAConst()
			if aConst != nil && aConst.GetIval() != nil {
				currentLimit := int64(aConst.GetIval().Ival)
				if currentLimit > maxLimit {
					aConst.Val = &pg_query.A_Const_Ival{
						Ival: &pg_query.Integer{
							Ival: int32(maxLimit),
						},
					}
					modified = true
				}
			}
		}
	}

	if !modified {
		return "", false, nil
	}

	rewritten, err := pg_query.Deparse(tree)
	if err != nil {
		return "", false, fmt.Errorf("failed to deparse rewritten AST: %w", err)
	}

	return strings.TrimSpace(rewritten), true, nil
}
