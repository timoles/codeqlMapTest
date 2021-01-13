/**
 * @name TODO
 * @kind problem
 * @problem.severity warning
 * @id java/example/TODO
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.DataFlow2
import semmle.code.java.Maps
import DataFlow::PathGraph


predicate hasObjectRestriction(Expr e) {
    exists(CheckForPutSecret conf |conf.hasFlow(_, DataFlow2::exprNode(e)))
  }

class CheckForPutSecret extends DataFlow2::Configuration {
    CheckForPutSecret() { this = "CheckForPutSecret" }

    override predicate isSource(DataFlow2::Node src) {
        src.asExpr().(CompileTimeConstantExpr).getStringValue() = "secret"
    }

    override predicate isSink(DataFlow2::Node srce) { any() }
}


class MapWithSecretInIt extends Expr {
    MapWithSecretInIt() {
      exists(MapPutCall put | hasObjectRestriction(put.getKey()) |
        put.getQualifier() = this and
        put.getMethod().(MapMethod).getReceiverKeyType().getName() = "String" and
        put.getMethod().(MapMethod).getReceiverValueType().getName() = "Object"
      )
    }
  }

class MyDataFlowConfiguration extends DataFlow::Configuration {
    MyDataFlowConfiguration() { this = "MyDataFlowConfiguration" }
  
    override predicate isSource(DataFlow::Node source) {
        source.asExpr().getType() instanceof MapType // Need to somewhow only get the initial env as source and not every time it is modified
    }
  
    override predicate isSink(DataFlow::Node sink) {
        exists(ConstructorCall ccall | 
            sink.asExpr() = ccall.getArgument(1) and
            ccall.getConstructor().getName() = "TestConstructor"
            )
    }  
    override predicate isBarrier(DataFlow::Node barrier) {
        exists(MapWithSecretInIt map  | map = barrier.asExpr())
      }
  }

from MyDataFlowConfiguration dataflow, DataFlow::PathNode source, DataFlow::PathNode sink
where
    dataflow.hasFlowPath(source, sink)
select source.getNode().getLocation(), source, sink, "I shouldn't exist"
//select arg, map
