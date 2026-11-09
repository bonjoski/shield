package dbguard

import (
	"fmt"
	"math"
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
	HasDisallowedStatement    bool
	DisallowedStatementType   string
	HasMutation               bool
	StatementCount            int
	HasSelect                 bool
	NeedsLimitCap             bool
	Statements                []string
}

var dangerousPGFunctions = map[string]bool{
	"pg_read_file":        true,
	"pg_read_binary_file": true,
	"pg_ls_dir":           true,
	"pg_ls_logdir":        true,
	"pg_ls_waldir":        true,
	"pg_ls_tmpdir":        true,
	"pg_stat_file":        true,
	"lo_import":           true,
	"lo_export":           true,
	"pg_terminate_backend": true,
	"pg_cancel_backend":   true,
	"pg_reload_conf":      true,
	"pg_rotate_logfile":   true,
	"pg_execute_server_program": true,
	"set_config":          true,
	"dblink":              true,
	"dblink_exec":         true,
	"dblink_connect":      true,
	"dblink_connect_u":    true,
}

// Parse parses an SQL string into a PostgreSQL AST.
func Parse(sql string) (*pg_query.ParseResult, error) {
	return pg_query.Parse(sql)
}

// Inspect examines the parsed AST tree using a strict deny-by-default statement allowlist.
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
		inspectNode(rawStmt.Stmt, result)
	}

	return result, nil
}

// inspectNode recursively inspects a statement node under a strict deny-by-default allowlist.
// Only SelectStmt (without SELECT INTO or locking), InsertStmt, UpdateStmt, DeleteStmt, and
// unwrapped ExplainStmt are eligible for policy evaluation; all other AST statement types fail closed.
func inspectNode(node *pg_query.Node, res *InspectionResult) {
	if node == nil || node.Node == nil {
		return
	}

	// 1. Classify known DDL statements first so specific DDL diagnostics are preserved.
	if ddlType := classifyDDLNode(node); ddlType != "" {
		res.HasDDL = true
		if res.DDLType == "" {
			res.DDLType = ddlType
		}
		return
	}

	// 2. Classify known Privilege Escalation statements.
	if privType := classifyPrivilegeNode(node); privType != "" {
		res.HasPrivilegeEscalation = true
		if res.PrivilegeType == "" {
			res.PrivilegeType = privType
		}
		return
	}

	// 3. Strict Deny-By-Default Statement Allowlist
	switch stmt := node.Node.(type) {
	case *pg_query.Node_SelectStmt:
		sel := stmt.SelectStmt
		if sel == nil {
			return
		}
		if sel.IntoClause != nil {
			res.HasDDL = true
			if res.DDLType == "" {
				res.DDLType = "SELECT INTO"
			}
			return
		}
		if len(sel.LockingClause) > 0 {
			markDisallowed(res, "SELECT FOR LOCKING")
			return
		}

		res.HasSelect = true
		if sel.LimitCount == nil || sel.LimitOption != pg_query.LimitOption_LIMIT_OPTION_COUNT {
			res.NeedsLimitCap = true
		}

		if sel.WithClause != nil {
			inspectWithClause(sel.WithClause, res)
		}
		if sel.Larg != nil {
			inspectNode(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: sel.Larg}}, res)
		}
		if sel.Rarg != nil {
			inspectNode(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: sel.Rarg}}, res)
		}
		inspectNodeSlice(sel.FromClause, res)
		inspectExprNode(sel.WhereClause, res)
		inspectNodeSlice(sel.TargetList, res)
		inspectExprNode(sel.HavingClause, res)
		inspectExprNode(sel.LimitCount, res)
		inspectExprNode(sel.LimitOffset, res)

	case *pg_query.Node_InsertStmt:
		ins := stmt.InsertStmt
		if ins == nil {
			return
		}
		res.HasMutation = true
		if ins.WithClause != nil {
			inspectWithClause(ins.WithClause, res)
		}
		if ins.SelectStmt != nil {
			inspectNode(ins.SelectStmt, res)
		}
		inspectNodeSlice(ins.ReturningList, res)

	case *pg_query.Node_UpdateStmt:
		update := stmt.UpdateStmt
		if update == nil {
			return
		}
		res.HasMutation = true
		if update.WhereClause == nil {
			res.HasUnconstrainedMutation = true
			rel := "relation"
			if update.Relation != nil && update.Relation.Relname != "" {
				rel = update.Relation.Relname
			}
			if res.UnconstrainedMutationType == "" {
				res.UnconstrainedMutationType = fmt.Sprintf("UPDATE %s without WHERE", rel)
			}
		}
		if update.WithClause != nil {
			inspectWithClause(update.WithClause, res)
		}
		inspectNodeSlice(update.FromClause, res)
		inspectExprNode(update.WhereClause, res)
		inspectNodeSlice(update.TargetList, res)
		inspectNodeSlice(update.ReturningList, res)

	case *pg_query.Node_DeleteStmt:
		del := stmt.DeleteStmt
		if del == nil {
			return
		}
		res.HasMutation = true
		if del.WhereClause == nil {
			res.HasUnconstrainedMutation = true
			rel := "relation"
			if del.Relation != nil && del.Relation.Relname != "" {
				rel = del.Relation.Relname
			}
			if res.UnconstrainedMutationType == "" {
				res.UnconstrainedMutationType = fmt.Sprintf("DELETE FROM %s without WHERE", rel)
			}
		}
		if del.WithClause != nil {
			inspectWithClause(del.WithClause, res)
		}
		inspectNodeSlice(del.UsingClause, res)
		inspectExprNode(del.WhereClause, res)
		inspectNodeSlice(del.ReturningList, res)

	case *pg_query.Node_ExplainStmt:
		exp := stmt.ExplainStmt
		if exp == nil || exp.Query == nil {
			markDisallowed(res, "EXPLAIN")
			return
		}
		innerRes := &InspectionResult{}
		inspectNode(exp.Query, innerRes)
		mergeInspectionResult(res, innerRes)

		if isExplainAnalyze(exp) && (innerRes.HasMutation || innerRes.HasDDL || innerRes.HasPrivilegeEscalation || innerRes.HasDisallowedStatement) {
			markDisallowed(res, "EXPLAIN ANALYZE with write/DDL query")
		}

	default:
		// Deny-by-default: DoStmt, PrepareStmt, ExecuteStmt, CopyStmt, CallStmt,
		// VariableSetStmt, ListenStmt, NotifyStmt, LockStmt, TransactionStmt, etc.
		markDisallowed(res, statementNodeLabel(node))
	}
}

func markDisallowed(res *InspectionResult, label string) {
	res.HasDisallowedStatement = true
	if res.DisallowedStatementType == "" {
		res.DisallowedStatementType = label
	}
}

func mergeInspectionResult(dst, src *InspectionResult) {
	if src.HasDDL {
		dst.HasDDL = true
		if dst.DDLType == "" {
			dst.DDLType = src.DDLType
		}
	}
	if src.HasPrivilegeEscalation {
		dst.HasPrivilegeEscalation = true
		if dst.PrivilegeType == "" {
			dst.PrivilegeType = src.PrivilegeType
		}
	}
	if src.HasUnconstrainedMutation {
		dst.HasUnconstrainedMutation = true
		if dst.UnconstrainedMutationType == "" {
			dst.UnconstrainedMutationType = src.UnconstrainedMutationType
		}
	}
	if src.HasDisallowedStatement {
		markDisallowed(dst, src.DisallowedStatementType)
	}
	if src.HasMutation {
		dst.HasMutation = true
	}
	if src.HasSelect {
		dst.HasSelect = true
	}
	if src.NeedsLimitCap {
		dst.NeedsLimitCap = true
	}
}

func isExplainAnalyze(exp *pg_query.ExplainStmt) bool {
	for _, opt := range exp.Options {
		if opt == nil {
			continue
		}
		def := opt.GetDefElem()
		if def == nil || !strings.EqualFold(def.Defname, "analyze") {
			continue
		}
		if def.Arg == nil {
			return true
		}
		if b := def.Arg.GetBoolean(); b != nil {
			return b.Boolval
		}
		if iv := def.Arg.GetInteger(); iv != nil {
			return iv.Ival != 0
		}
		if sv := def.Arg.GetString_(); sv != nil {
			val := strings.ToLower(strings.TrimSpace(sv.Sval))
			return val != "false" && val != "off" && val != "0"
		}
		return true
	}
	return false
}

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

func inspectNodeSlice(nodes []*pg_query.Node, res *InspectionResult) {
	for _, n := range nodes {
		inspectExprNode(n, res)
	}
}

func inspectExprNode(node *pg_query.Node, res *InspectionResult) {
	if node == nil || node.Node == nil {
		return
	}

	switch n := node.Node.(type) {
	case *pg_query.Node_RangeSubselect:
		if n.RangeSubselect != nil && n.RangeSubselect.Subquery != nil {
			inspectNode(n.RangeSubselect.Subquery, res)
		}
	case *pg_query.Node_JoinExpr:
		if n.JoinExpr != nil {
			inspectExprNode(n.JoinExpr.Larg, res)
			inspectExprNode(n.JoinExpr.Rarg, res)
			inspectExprNode(n.JoinExpr.Quals, res)
		}
	case *pg_query.Node_SubLink:
		if n.SubLink != nil {
			inspectExprNode(n.SubLink.Testexpr, res)
			if n.SubLink.Subselect != nil {
				inspectNode(n.SubLink.Subselect, res)
			}
		}
	case *pg_query.Node_ResTarget:
		if n.ResTarget != nil {
			inspectExprNode(n.ResTarget.Val, res)
		}
	case *pg_query.Node_BoolExpr:
		if n.BoolExpr != nil {
			inspectNodeSlice(n.BoolExpr.Args, res)
		}
	case *pg_query.Node_AExpr:
		if n.AExpr != nil {
			inspectExprNode(n.AExpr.Lexpr, res)
			inspectExprNode(n.AExpr.Rexpr, res)
		}
	case *pg_query.Node_FuncCall:
		if n.FuncCall != nil {
			fnName := extractFuncName(n.FuncCall)
			if dangerousPGFunctions[fnName] {
				markDisallowed(res, "FUNCTION "+fnName)
			}
			inspectNodeSlice(n.FuncCall.Args, res)
		}
	case *pg_query.Node_RangeFunction:
		if n.RangeFunction != nil {
			inspectNodeSlice(n.RangeFunction.Functions, res)
		}
	case *pg_query.Node_List:
		if n.List != nil {
			inspectNodeSlice(n.List.Items, res)
		}
	case *pg_query.Node_TypeCast:
		if n.TypeCast != nil {
			inspectExprNode(n.TypeCast.Arg, res)
		}
	case *pg_query.Node_CoalesceExpr:
		if n.CoalesceExpr != nil {
			inspectNodeSlice(n.CoalesceExpr.Args, res)
		}
	case *pg_query.Node_CaseExpr:
		if n.CaseExpr != nil {
			inspectExprNode(n.CaseExpr.Arg, res)
			inspectNodeSlice(n.CaseExpr.Args, res)
			inspectExprNode(n.CaseExpr.Defresult, res)
		}
	case *pg_query.Node_CaseWhen:
		if n.CaseWhen != nil {
			inspectExprNode(n.CaseWhen.Expr, res)
			inspectExprNode(n.CaseWhen.Result, res)
		}
	}
}

func extractFuncName(fc *pg_query.FuncCall) string {
	if fc == nil || len(fc.Funcname) == 0 {
		return ""
	}
	last := fc.Funcname[len(fc.Funcname)-1]
	if last != nil && last.GetString_() != nil {
		return strings.ToLower(last.GetString_().Sval)
	}
	return ""
}

func classifyDDLNode(node *pg_query.Node) string {
	if drop := node.GetDropStmt(); drop != nil {
		return fmt.Sprintf("DROP %v", drop.RemoveType)
	}
	switch {
	case node.GetDropdbStmt() != nil:
		return "DROP DATABASE"
	case node.GetDropRoleStmt() != nil:
		return "DROP ROLE"
	case node.GetDropTableSpaceStmt() != nil:
		return "DROP TABLESPACE"
	case node.GetDropUserMappingStmt() != nil:
		return "DROP USER MAPPING"
	case node.GetDropOwnedStmt() != nil:
		return "DROP OWNED"
	case node.GetDropSubscriptionStmt() != nil:
		return "DROP SUBSCRIPTION"
	case node.GetTruncateStmt() != nil:
		return "TRUNCATE"
	case node.GetRenameStmt() != nil:
		return "RENAME"
	case node.GetAlterTableStmt() != nil:
		return "ALTER TABLE"
	case node.GetAlterDomainStmt() != nil:
		return "ALTER DOMAIN"
	case node.GetAlterFunctionStmt() != nil:
		return "ALTER FUNCTION"
	case node.GetAlterPolicyStmt() != nil:
		return "ALTER POLICY"
	case node.GetAlterSeqStmt() != nil:
		return "ALTER SEQUENCE"
	case node.GetAlterDatabaseStmt() != nil || node.GetAlterDatabaseSetStmt() != nil || node.GetAlterDatabaseRefreshCollStmt() != nil:
		return "ALTER DATABASE"
	case node.GetAlterDefaultPrivilegesStmt() != nil:
		return "ALTER DEFAULT PRIVILEGES"
	case node.GetAlterTableSpaceOptionsStmt() != nil || node.GetAlterTableMoveAllStmt() != nil:
		return "ALTER TABLESPACE"
	case node.GetAlterExtensionStmt() != nil || node.GetAlterExtensionContentsStmt() != nil:
		return "ALTER EXTENSION"
	case node.GetAlterFdwStmt() != nil || node.GetAlterForeignServerStmt() != nil || node.GetAlterUserMappingStmt() != nil:
		return "ALTER FDW/SERVER"
	case node.GetAlterSystemStmt() != nil:
		return "ALTER SYSTEM"
	case node.GetAlterTypeStmt() != nil || node.GetAlterEnumStmt() != nil:
		return "ALTER TYPE"
	case node.GetCreateStmt() != nil || node.GetCreateTableAsStmt() != nil:
		return "CREATE TABLE"
	case node.GetCreateSchemaStmt() != nil:
		return "CREATE SCHEMA"
	case node.GetCreatedbStmt() != nil:
		return "CREATE DATABASE"
	case node.GetCreateExtensionStmt() != nil:
		return "CREATE EXTENSION"
	case node.GetViewStmt() != nil:
		return "CREATE VIEW"
	case node.GetIndexStmt() != nil:
		return "CREATE INDEX"
	case node.GetCreateFunctionStmt() != nil:
		return "CREATE FUNCTION"
	case node.GetCreateTrigStmt() != nil:
		return "CREATE TRIGGER"
	case node.GetCreatePolicyStmt() != nil:
		return "CREATE POLICY"
	case node.GetRuleStmt() != nil:
		return "CREATE RULE"
	}
	return ""
}

func classifyPrivilegeNode(node *pg_query.Node) string {
	switch {
	case node.GetGrantStmt() != nil:
		return "GRANT"
	case node.GetGrantRoleStmt() != nil:
		return "GRANT ROLE"
	case node.GetCreateRoleStmt() != nil:
		return "CREATE ROLE/USER"
	case node.GetAlterRoleStmt() != nil || node.GetAlterRoleSetStmt() != nil:
		return "ALTER ROLE"
	case node.GetSecLabelStmt() != nil:
		return "SECURITY LABEL"
	}
	if vs := node.GetVariableSetStmt(); vs != nil {
		name := strings.ToLower(vs.Name)
		if name == "role" || name == "session_authorization" {
			return "SET " + strings.ToUpper(name)
		}
	}
	return ""
}

func statementNodeLabel(node *pg_query.Node) string {
	switch {
	case node.GetDoStmt() != nil:
		return "DO"
	case node.GetPrepareStmt() != nil:
		return "PREPARE"
	case node.GetExecuteStmt() != nil:
		return "EXECUTE"
	case node.GetDeallocateStmt() != nil:
		return "DEALLOCATE"
	case node.GetCopyStmt() != nil:
		return "COPY"
	case node.GetCallStmt() != nil:
		return "CALL"
	case node.GetVariableSetStmt() != nil:
		return "SET"
	case node.GetVariableShowStmt() != nil:
		return "SHOW"
	case node.GetListenStmt() != nil:
		return "LISTEN"
	case node.GetNotifyStmt() != nil:
		return "NOTIFY"
	case node.GetLockStmt() != nil:
		return "LOCK"
	case node.GetTransactionStmt() != nil:
		return "TRANSACTION"
	case node.GetDeclareCursorStmt() != nil:
		return "DECLARE CURSOR"
	case node.GetFetchStmt() != nil:
		return "FETCH"
	case node.GetVacuumStmt() != nil:
		return "VACUUM"
	case node.GetMergeStmt() != nil:
		return "MERGE"
	default:
		return fmt.Sprintf("%T", node.Node)
	}
}

// EnforceLimit rewrites unbounded or non-constant SELECT statements (including RangeSubselects,
// CTEs, and unwrapped EXPLAIN SELECTs) to strictly clamp rows at maxLimit.
func EnforceLimit(tree *pg_query.ParseResult, maxLimit int64) (string, bool, error) {
	if tree == nil || len(tree.Stmts) == 0 || maxLimit <= 0 {
		return "", false, nil
	}

	clampedMax := maxLimit
	if clampedMax > math.MaxInt32 {
		clampedMax = math.MaxInt32
	}

	modified := false
	for _, rawStmt := range tree.Stmts {
		if rawStmt == nil || rawStmt.Stmt == nil {
			continue
		}
		if enforceNodeLimit(rawStmt.Stmt, clampedMax) {
			modified = true
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

func enforceNodeLimit(node *pg_query.Node, maxLimit int64) bool {
	if node == nil || node.Node == nil {
		return false
	}

	switch stmt := node.Node.(type) {
	case *pg_query.Node_SelectStmt:
		return enforceSelectStmtLimit(stmt.SelectStmt, maxLimit)
	case *pg_query.Node_ExplainStmt:
		if stmt.ExplainStmt != nil && stmt.ExplainStmt.Query != nil {
			return enforceNodeLimit(stmt.ExplainStmt.Query, maxLimit)
		}
	case *pg_query.Node_InsertStmt:
		mod := false
		if stmt.InsertStmt != nil {
			if enforceWithClauseLimit(stmt.InsertStmt.WithClause, maxLimit) {
				mod = true
			}
			if stmt.InsertStmt.SelectStmt != nil {
				if sel := stmt.InsertStmt.SelectStmt.GetSelectStmt(); sel != nil && len(sel.ValuesLists) == 0 {
					if enforceSelectStmtLimit(sel, maxLimit) {
						mod = true
					}
				}
			}
		}
		return mod
	case *pg_query.Node_UpdateStmt:
		mod := false
		if stmt.UpdateStmt != nil {
			if enforceWithClauseLimit(stmt.UpdateStmt.WithClause, maxLimit) {
				mod = true
			}
			for _, f := range stmt.UpdateStmt.FromClause {
				if enforceFromClauseLimit(f, maxLimit) {
					mod = true
				}
			}
		}
		return mod
	case *pg_query.Node_DeleteStmt:
		mod := false
		if stmt.DeleteStmt != nil {
			if enforceWithClauseLimit(stmt.DeleteStmt.WithClause, maxLimit) {
				mod = true
			}
			for _, u := range stmt.DeleteStmt.UsingClause {
				if enforceFromClauseLimit(u, maxLimit) {
					mod = true
				}
			}
		}
		return mod
	}
	return false
}

func enforceWithClauseLimit(with *pg_query.WithClause, maxLimit int64) bool {
	if with == nil {
		return false
	}
	modified := false
	for _, cteNode := range with.Ctes {
		if cteNode == nil {
			continue
		}
		if cte := cteNode.GetCommonTableExpr(); cte != nil && cte.Ctequery != nil {
			if sel := cte.Ctequery.GetSelectStmt(); sel != nil {
				if enforceSelectStmtLimit(sel, maxLimit) {
					modified = true
				}
			}
		}
	}
	return modified
}

func enforceFromClauseLimit(node *pg_query.Node, maxLimit int64) bool {
	if node == nil || node.Node == nil {
		return false
	}
	modified := false
	switch n := node.Node.(type) {
	case *pg_query.Node_RangeSubselect:
		if n.RangeSubselect != nil && n.RangeSubselect.Subquery != nil {
			if enforceNodeLimit(n.RangeSubselect.Subquery, maxLimit) {
				modified = true
			}
		}
	case *pg_query.Node_JoinExpr:
		if n.JoinExpr != nil {
			if enforceFromClauseLimit(n.JoinExpr.Larg, maxLimit) {
				modified = true
			}
			if enforceFromClauseLimit(n.JoinExpr.Rarg, maxLimit) {
				modified = true
			}
		}
	}
	return modified
}

func enforceSelectStmtLimit(sel *pg_query.SelectStmt, maxLimit int64) bool {
	if sel == nil {
		return false
	}

	modified := false
	if enforceWithClauseLimit(sel.WithClause, maxLimit) {
		modified = true
	}
	for _, fromItem := range sel.FromClause {
		if enforceFromClauseLimit(fromItem, maxLimit) {
			modified = true
		}
	}

	if len(sel.ValuesLists) > 0 {
		return modified
	}

	if !isConstantBoundedLimit(sel, maxLimit) {
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
	}

	return modified
}

func isConstantBoundedLimit(sel *pg_query.SelectStmt, maxLimit int64) bool {
	if sel == nil || sel.LimitCount == nil {
		return false
	}
	if sel.LimitOption != pg_query.LimitOption_LIMIT_OPTION_COUNT {
		return false
	}
	aConst := sel.LimitCount.GetAConst()
	if aConst == nil || aConst.Isnull {
		return false
	}
	ival := aConst.GetIval()
	if ival == nil {
		return false
	}
	currentLimit := int64(ival.Ival)
	return currentLimit >= 0 && currentLimit <= maxLimit
}
