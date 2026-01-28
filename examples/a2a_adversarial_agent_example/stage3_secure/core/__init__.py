"""
Core Module - Stage 3

Core system infrastructure:
- protocol.py: Message protocol definitions
- task_queue.py: Task management
- utils.py: Utility functions
"""

# Import available core modules
try:
    from .protocol import Protocol, Message, MessageType
except ImportError:
    Protocol = Message = MessageType = None

try:
    from .task_queue import TaskQueue, Task, TaskStatus
except ImportError:
    TaskQueue = Task = TaskStatus = None

try:
    from .utils import *
except ImportError:
    pass

__all__ = []

# Add available exports
if Protocol is not None:
    __all__.extend(['Protocol', 'Message', 'MessageType'])

if TaskQueue is not None:
    __all__.extend(['TaskQueue', 'Task', 'TaskStatus'])

__version__ = '3.0.0'