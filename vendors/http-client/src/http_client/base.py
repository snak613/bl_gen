from abc import ABC, abstractmethod

from .models import HttpResponse


class BaseHttpClient(ABC):
    @abstractmethod
    def request(self) -> HttpResponse: ...

    @abstractmethod
    def get(self) -> HttpResponse: ...

    @abstractmethod
    def post(self) -> HttpResponse: ...

    def patch(self) -> HttpResponse: ...

    def delete(self) -> HttpResponse: ...
