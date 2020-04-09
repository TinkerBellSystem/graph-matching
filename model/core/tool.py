import logging
logger = logging.getLogger(__name__)


def ast_snippet(ast_snippet):
    """AST snippet from pycparser without formatting for quick printing.

    Argument:
    ast_snippet     -- the ast snippet
    
    Returns:
    an ast snippet without formatting (i.e., whitespace)"""
    return repr(ast_snippet).replace('\n', ' ').replace(' ', '')


def local_name(func_name, var_name):
    """An object's local name is the concatenation of the name
    of the function it is located in and the variable name it
    is assigned in the function.

    Arguments:
    func_name       -- the name of the function an object is in
    var_name        -- the name of the object given in the function
    
    Returns:
    a string local name that is a concatenantion of both"""
    return "{}.{}".format(func_name, var_name)


def get_global_name(name, name_dict):
    """Recursively get the true identity of a MotifNode.
    We must do it recursively because a caller may
    pass its argument to a callee (so the caller's argument
    is mapped to the callee's parameter), but the callee
    might then again call another function and pass the
    same argument to the callee's callee's paramter.

    The global scope is within the CamFlow hooks.

    Arguments:
    name        -- the name used to find its global name
    name_dict   -- caller argument to callee parameter name dict

    Returns:
    the @name's global name"""
    #TODO: naming ambiguity still exists due to recursive functions

    while name_dict.get(name, None) is not None:
        name = name_dict.get(name, None)

    return name


def get_func_args(call):
    """Extract function argument names in a subroutine function call.

    Argument:
    call       -- function call

    Returns:
    An ordered list of function call's argument names"""
    args = list()
     
    # Case 0: 
    if type(call.args).__name__ == "NoneType":
        pass
    # If it is a list of function call arguments
    elif type(call.args).__name__ == "ExprList":
        for arg in call.args.exprs:
            if type(arg).__name__ == "ID":
                # Case 1: func(arg1) -> arg1
                args.append(arg.name)
            elif type(arg).__name__ == "UnaryOp":
                # Case 2: e.g., func(&arg2) -> arg2
                args.append(arg.expr.name)
            elif type(arg).__name__ == "FuncCall":
                #TODO: Case 3: func(inner_func(...)) -> ...
                logger.warning("\x1b[6;30;43m[!]\x1b[0m Function argument type {} in argument list \
                        is not considered (core/tool.py/get_func_args)".format(type(arg).__name__))
            elif type(arg).__name__ == "Constant":
                # Case 4: func(ARG_CONST) -> ARG_CONST
                args.append(arg.value)
            elif type(arg).__name__ == "StructRef":
                #TODO: Case 5:???
                logger.warning("\x1b[6;30;43m[!]\x1b[0m Function argument type {} in argument list \
                        is not considered (core/tool.py/get_func_args)".format(type(arg).__name__))
            elif type(arg).__name__ == 'BinaryOp':
                #TODO: Case 6:???
                logger.warning("\x1b[6;30;43m[!]\x1b[0m Function argument type {} in argument list \
                        is not considered (core/tool.py/get_func_args)".format(type(arg).__name__))
            else:
                logger.warning("\x1b[6;30;43m[!]\x1b[0m Function argument type {} in argument list is \
                        not considered (core/tool.py/get_func_args)".format(type(arg).__name__))
    else:
        logger.warning("\x1b[6;30;43m[!]\x1b[0m Function argument type {} is not considered \
                (core/tool.py/get_func_args)".format(type(call.args).__name__))
    
    return args


def create_name_dict(args, params, name_dict):
    #TODO: Check if args or params should be the key and value?
    #TODO: name_dict is not inherited in this implementation?!
    """Add a list of function definition parameters as keys that are mapped to
    function call arguments as values. Each argument corresponds to the paramter
    in the same position.

    Arguments:
    args        -- a list of function call arguments
    params      -- a list of function definition parameters
    name_dict   -- name dictionary it inherits from

    Returns:
    a new name dict"""
    if len(args) != len(params):
        logger.fatal("\x1b[6;30;41m[x]\x1b[0m Invalid argument or parameter list.")
        raise RuntimeError("The argument list should have the same number of items as the parameter list")
    
    new_dict = dict()
    logger.debug("\x1b[6;30;42m[+]\x1b[0m Adding new items to name dictionary (core/tool.py/add_name_dict)")

    for i in range(len(params)):
        arg = get_global_name(args[i], name_dict)
        new_dict[params[i]] = arg

    return new_dict


def get_rel(rel_dict, rel_type):
    """Get CamFlow's provenance relation name string from its definition.

    Arguments:
    rel_dict        -- the dictionary constructed from create_relation_dict()
    rel_type        -- the relation definition in the code

    Returns:
    a relation name string."""
    try:
        return rel_dict[rel_type]
    except Exception as e:
        logger.fatal("Relation type {} is unknown".format(rel_type))
        raise ValueError(repr(e))

