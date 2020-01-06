import traceback
import logging

logger = logging.getLogger('webcheckr')

class ModuleNotFinished(Exception):
    pass

class WebcheckrModule:
    def __init__(self, name, url):
        self.name = name
        self.status = None
        self.url = url

    def run(self):
        try:
            self.status = 'started'
            logger.info(f"[{self.url}] We are starting {self.name} module")
            self._work()
            logger.info(f"[{self.url}] Ending {self.name} module")
            self.status = 'terminated'
            logger.debug(f"[{self.url}] {self.get_result()}")
            return self.get_result()
        except:
            self.status = 'error'
            traceback.print_exc()
            raise Exception()

    def _work(self):
        raise NotImplementedError("A Module class needs to implement a _work method.")

    def to_html(self):
        return ""

    def to_string(self):
        return ""

    def get_result(self):
        if self.status != 'started':
            return { 
                    "name": self.name,
                    "status": self.status,
                    "visual": {
                        "html": self.to_html(),
                        "string": self.to_string(),
                        },
                    "content": self._result()
                    }
        else:
            raise ModuleNotFinished("The Module is still working, the result isn't available")


    def _result(self):
        raise NotImplementedError("A Module class needs to implement a _return method.")


