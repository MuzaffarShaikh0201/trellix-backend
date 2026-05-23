"""
Models initialization.
"""

from .enums import (
    AuthTypeEnum,
    ProjectPriorityEnum,
    ProjectStageEnum,
    ProjectStatusEnum,
    ProjectTechStackTypeEnum,
    ProjectTypeEnum,
    TaskDomainEnum,
    TaskPriorityEnum,
    TaskStatusEnum,
    TaskTypeEnum,
)
from .database import Base, Project, ProjectTechStack, Task, User
from .misc import Root200Response, Health200Response
from .auth import (
    RegisterParams,
    Register201Response,
    SessionData,
    UserCreds,
    LoginParams,
    Login200Response,
    RefreshParams,
    Refresh200Response,
    Logout200Response,
)
from .project import (
    CreateProjectParams,
    CreateProject201Response,
    GetAllProjectsParams,
    GetAllProjects200Response,
    GetProject200Response,
    ToggleProjectFavorite200Response,
    UpdateProjectParams,
    UpdateProject200Response,
    DeleteProject200Response,
)
from .user import (
    GetUser200Response,
    UpdateUserParams,
    UpdateUser200Response,
    UpdateUserPasswordParams,
    UpdateUserPassword200Response,
)


__all__ = [
    "AuthTypeEnum",
    "ProjectStatusEnum",
    "ProjectPriorityEnum",
    "ProjectTypeEnum",
    "ProjectStageEnum",
    "ProjectTechStackTypeEnum",
    "TaskStatusEnum",
    "TaskTypeEnum",
    "TaskPriorityEnum",
    "TaskDomainEnum",
    "Base",
    "Health200Response",
    "Project",
    "ProjectTechStack",
    "Task",
    "Root200Response",
    "User",
    "RegisterParams",
    "Register201Response",
    "SessionData",
    "UserCreds",
    "LoginParams",
    "Login200Response",
    "RefreshParams",
    "Refresh200Response",
    "CreateProjectParams",
    "CreateProject201Response",
    "Logout200Response",
    "GetAllProjectsParams",
    "GetAllProjects200Response",
    "GetProject200Response",
    "GetUser200Response",
    "UpdateUserParams",
    "UpdateUser200Response",
    "UpdateUserPasswordParams",
    "UpdateUserPassword200Response",
    "ToggleProjectFavorite200Response",
    "UpdateProjectParams",
    "UpdateProject200Response",
    "DeleteProject200Response",
]
