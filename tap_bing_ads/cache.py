import suds.cache


class InMemoryObjectCache(suds.cache.ObjectCache):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._mem = {}

    def get(self, id_):
        if id_ in self._mem:
            return self._mem[id_]
        return super().get(id_)

    def put(self, id_, obj):
        obj = super().put(id_, obj)
        self._mem[id_] = obj
        return obj

    def purge(self, id_):
        super().purge(id_)
        self._mem.pop(id_, None)

    def clear(self):
        super().clear()
        self._mem.clear()


IN_MEMORY_OBJECT_CACHE = InMemoryObjectCache(days=1)
