from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import PlainTextResponse
from ..services.build_service import BuildService
from ...datacls.messages import BuildStartRequest, BuildStartResponse, BuildStatusResponse, BuildLogsResponse, ArtifactsResponse
from ..deps import get_build_service

router = APIRouter()

@router.post("/projects/{project_name}/build", response_model=BuildStartResponse, status_code=202)
def start_build(project_name: str, request: BuildStartRequest, build_service: BuildService = Depends(get_build_service)):
    build_id = build_service.start_build(project_name, request.debug, request.generate_graph)
    return {"build_id": build_id}

@router.get("/builds/{build_id}/status", response_model=BuildStatusResponse)
def get_build_status(build_id: str, build_service: BuildService = Depends(get_build_service)):
    status = build_service.get_build_status(build_id)
    if not status:
        raise HTTPException(status_code=404, detail="Build not found")
    return status

@router.get("/builds/{build_id}/logs", response_model=BuildLogsResponse)
def get_build_logs(build_id: str, since: int = 0, build_service: BuildService = Depends(get_build_service)):
    logs = build_service.get_build_logs(build_id, since)
    if not logs:
        raise HTTPException(status_code=404, detail="Build not found")
    return logs

@router.get("/builds/{build_id}/artifacts", response_model=ArtifactsResponse)
def get_build_artifacts(build_id: str, build_service: BuildService = Depends(get_build_service)):
    status = build_service.get_build_status(build_id)
    if not status:
        raise HTTPException(status_code=404, detail="Build not found")
    
    # Get project name from build status
    project_name = status.get("project_name")
    if not project_name:
        raise HTTPException(status_code=400, detail="Project name not found in build status")
    
    artifacts = build_service.get_build_artifacts(project_name)
    return {"files": artifacts}

@router.get("/builds/{build_id}/artifacts/content", response_class=PlainTextResponse)
def get_build_artifact_content(
    build_id: str, 
    path: str = Query(..., description="recursor/Dockerfile"),
    build_service: BuildService = Depends(get_build_service)
):
    """
    Get the file content of a specified build artifact

    Args:
        build_id: Build ID
        path: File path relative to the output directory

    Returns:
        Plain text content of the file
    """
    content = build_service.get_build_artifact_content(build_id, path)
    if content is None:
        raise HTTPException(status_code=404, detail="Build not found or file not found")
    return content