import pycparser
import argparse

def main(args):
    # We use PyCParser to parse CamFlow C files.
    # PyCParser must begin at the top level of the C files,
    # with either declarations or function definitions.
    # A C parser must also have all the types declared
    # to build the correct AST.

    # Parse the preprocessed hooks.c file.
    ast = pycparser.parse_file("{}/security/provenance/hooks_pp.c".format(args.camflow))
    
    # Uncomment the following line to see the AST in a nice, human
    # readable way. show() is the most useful tool in exploring ASTs
    # created by pycparser. See the c_ast.py file for the options you can pass to it.
    # ast.show(showcoord=True)

    # We've seen that the top node is FileAST. This is always the
    # top node of the AST. Its children are "external declarations",
    # and are stored in a list called ext[] (see _c_ast.cfg for the
    # names and types of Nodes and their children).

    # We declare a dictionary that saves a RTM tree for each hook.
    hooks = dict()

    # We go through each function definition that defines a hook.
    for ext in ast.ext:
        if type(ext).__name__ == 'FuncDef':
            # A FuncDef consists of a declaration, a list of parameter
            # declarations (for K&R style function definitions), and a body.
            # function_decl, like any other declaration, is a Decl.
            # Its type child is a FuncDecl, which has a return type and arguments stored in a ParamList node
            function_decl = ext.decl
            # From declaration, we can also get the function name.
            function_name = function_decl.name
            function_decl.type.show()
            function_decl.type.args.show()
            # The following displays the name and type of each argument:
            # for param_decl in function_decl.type.args.params:
                # print('Arg name: %s' % param_decl.name)
                # print('Type:')
                # param_decl.type.show(offset=6)
            exit(1)



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--camflow", required=True, 
                        help="the top-most directory path of CamFlow code base, which should end with '/camflow-dev/'")
    args = parser.parse_args()
    main(args)
