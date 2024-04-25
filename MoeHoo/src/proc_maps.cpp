#include "proc_maps.h"

hak::proc_maps::proc_maps(uint64_t start, uint64_t end)
{
    this->_start = start;
    this->_end = end;
}

void hak::proc_maps::insert(std::shared_ptr<hak::proc_maps> maps)
{ // NOLINT(*-unnecessary-value-param)
    if (maps == shared_from_this())
        return;
    if (this->_tail == nullptr)
    {
        this->_tail = maps;
    }
    else
    {
        auto temp = this->_tail;
        maps->_head = shared_from_this();
        maps->last()->_tail = temp;
        this->_tail = maps;
    }
}

void hak::proc_maps::remove()
{
    _head->_tail = _tail;
    _tail->_head = _head;
}

auto hak::proc_maps::size() -> size_t
{
    size_t size = 1;
    auto curr = shared_from_this();
    while ((curr = curr->next()) != nullptr)
    {
        size++;
    }
    return size;
}

auto hak::proc_maps::start() const -> uint64_t
{
    return _start;
}

auto hak::proc_maps::end() const -> uint64_t
{
    return _end;
}

auto hak::proc_maps::next() -> std::shared_ptr<hak::proc_maps> &
{
    return _tail;
}

auto hak::proc_maps::last() -> std::shared_ptr<hak::proc_maps>
{
    auto curr = shared_from_this();
    std::shared_ptr<proc_maps> result = curr;
    while ((curr = curr->next()) != nullptr)
    {
        result = curr;
    }
    return result;
}
