#include "lowcardinality.h"

#include "string.h"
#include "nullable.h"
#include "../base/wire_format.h"

#include <cityhash/city.h>

#include <functional>
#include <string_view>
#include <type_traits>

namespace
{
using namespace clickhouse;

enum KeySerializationVersion
{
    SharedDictionariesWithAdditionalKeys = 1,
};

enum IndexType
{
    UInt8 = 0,
    UInt16,
    UInt32,
    UInt64,
};

constexpr uint64_t IndexTypeMask = 0b11111111;

enum IndexFlag
{
    /// Need to read dictionary if it wasn't.
    NeedGlobalDictionaryBit = 1u << 8u,
    /// Need to read additional keys. Additional keys are stored before indexes as value N and N keys after them.
    HasAdditionalKeysBit = 1u << 9u,
    /// Need to update dictionary. It means that previous granule has different dictionary.
    NeedUpdateDictionary = 1u << 10u
};

template <typename T>
auto getColumnFromVariant(const T & column_variant)
{
    return std::visit([](auto && arg) -> const Column * {
        return &arg;
    }, column_variant);
}

template <typename T>
auto getColumnFromVariant(T & column_variant)
{
    return std::visit([](auto && arg) -> Column * {
        return &arg;
    }, column_variant);
}

ColumnLowCardinality::IndexColumn createIndexColumn(IndexType type)
{
    switch (type)
    {
        case IndexType::UInt8:
            return ColumnUInt8{};
        case IndexType::UInt16:
            return ColumnUInt16{};
        case IndexType::UInt32:
            return ColumnUInt32{};
        case IndexType::UInt64:
            return ColumnUInt64{};
    }

    throw std::runtime_error("Invalid LowCardinality index type value: " + std::to_string(static_cast<uint64_t>(type)));
}

IndexType indexTypeFromIndexColumn(const ColumnLowCardinality::IndexColumn & index) {
    const auto type = getColumnFromVariant(index)->Type();
    switch (type->GetCode()) {
        case Type::UInt8:
            return IndexType::UInt8;
        case Type::UInt16:
            return IndexType::UInt16;
        case Type::UInt32:
            return IndexType::UInt32;
        case Type::UInt64:
            return IndexType::UInt64;
        default:
            throw std::runtime_error("Invalid index column type for LowCardinality column:" + type->GetName());
    }
}

inline void AppendToDictionary(ColumnRef dictionary, const ItemView & item) {
    if (auto c = dictionary->As<ColumnString>()) {
        c->Append(item.get<std::string_view>());
    }
    else if (auto c = dictionary->As<ColumnFixedString>()) {
        c->Append(item.get<std::string_view>());
    }
    else {
        throw std::runtime_error("Unexpected dictionary column type: " + dictionary->Type()->GetName());
    }
}

// Add special NULL-item, which is expected at pos(0) in dictionary,
// note that we distinguish empty string from NULL-value.
inline void AppendNullItemToDictionary(ColumnRef dictionary) {
    if (auto n = dictionary->As<ColumnNullable>()) {
        AppendToDictionary(dictionary, ItemView{});
    }
    else {
        AppendToDictionary(dictionary, ItemView{std::string_view{}});
    }
}

}

namespace clickhouse
{
ColumnLowCardinality::ColumnLowCardinality(ColumnRef dictionary_column)
    : Column(Type::CreateLowCardinality(dictionary_column->Type())),
      dictionary(dictionary_column),
      index(std::in_place_type_t<ColumnUInt32>{})
{
    if (dictionary->Size() != 0) {
        // When dictionary column was constructed with values, re-add values by copying to update index and unique_items_map.

        // Steal values into temporary column.
        auto values = dictionary->Slice(0, 0);
        values->Swap(*dictionary);

        AppendNullItemToDictionary(values);

        // Re-add values, updating index and unique_items_map.
        for (size_t i = 0; i < values->Size(); ++i)
            AppendUnsafe(values->GetItem(i));
    }
    else {
        AppendNullItemToDictionary(dictionary);
    }
}

ColumnLowCardinality::~ColumnLowCardinality()
{}

std::uint64_t ColumnLowCardinality::getDictionaryIndex(std::uint64_t item_index) const
{
    return std::visit([item_index](const auto & arg) -> std::uint64_t {
        return arg[item_index];
    }, index);
}

void ColumnLowCardinality::appendIndex(std::uint64_t item_index)
{
    // TODO (nemkov): handle case when index should go from UInt8 to UInt16, etc.
    std::visit([item_index](auto & arg) {
        arg.Append(item_index);
    }, index);
}

void ColumnLowCardinality::removeLastIndex() {
    std::visit([](auto & arg) {
        arg.Erase(arg.Size() - 1);
    }, index);
}

details::LowCardinalityHashKey ColumnLowCardinality::computeHashKey(const ItemView & data) {
    static const auto hasher = std::hash<ItemView::DataType>{};
    if (data.type == Type::Void) {
        // to distinguish NULL from ColumnNullable and empty string.
        return {0u, 0u};
    }

    const auto hash1 = hasher(data.data);
    const auto binary = data.AsBinaryData();
    const auto hash2 = CityHash64(binary.data(), binary.size());

    return details::LowCardinalityHashKey{hash1, hash2};
}

ColumnRef ColumnLowCardinality::GetDictionary()
{
    return dictionary;
}

void ColumnLowCardinality::Append(ColumnRef col)
{
    auto c = dynamic_cast<const ColumnLowCardinality*>(col.get());
    if (!c || !dictionary->Type()->IsEqual(c->dictionary->Type()))
        return;

    for (size_t i = 0; i < c->Size(); ++i) {
        AppendFrom(*c, i);
    }
}

namespace
{

auto Load(ColumnRef new_dictionary_column, CodedInputStream* input, size_t rows) {
    // This code tries to follow original implementation of ClickHouse's LowCardinality serialization with
    // NativeBlockOutputStream::writeData() for DataTypeLowCardinality
    // (see corresponding serializeBinaryBulkStateSuffix, serializeBinaryBulkStatePrefix, and serializeBinaryBulkWithMultipleStreams),
    // but with certain simplifications: no shared dictionaries, no on-the-fly dictionary updates.
    //
    // As for now those fetures not used in client-server protocol and minimal implimintation suffice,
    // however some day they may.

    // prefix
    uint64_t key_version;
    if (!WireFormat::ReadFixed(input, &key_version))
        throw std::runtime_error("Failed to read key serialization version.");

    if (key_version != KeySerializationVersion::SharedDictionariesWithAdditionalKeys)
        throw std::runtime_error("Invalid key serialization version value.");

    // body
    uint64_t index_serialization_type;
    if (!WireFormat::ReadFixed(input, &index_serialization_type))
        throw std::runtime_error("Failed to read index serializaton type.");

    ColumnLowCardinality::IndexColumn new_index = createIndexColumn(static_cast<IndexType>(index_serialization_type & IndexTypeMask));
    Column * new_index_column = getColumnFromVariant(new_index);

    // kinda-clone
//    ColumnRef new_dictionary_column = dictionary->Slice(0, 0);

    if (index_serialization_type & IndexFlag::NeedGlobalDictionaryBit)
        throw std::runtime_error("Global dictionary is not supported.");

    if ((index_serialization_type & IndexFlag::HasAdditionalKeysBit) == 0)
        throw std::runtime_error("HasAdditionalKeysBit is missing.");

    uint64_t number_of_keys;
    if (!WireFormat::ReadFixed(input, &number_of_keys))
        throw std::runtime_error("Failed to read number of rows in dictionary column.");

    if (!new_dictionary_column->Load(input, number_of_keys))
        throw std::runtime_error("Failed to read values of dictionary column.");

    uint64_t number_of_rows;
    if (!WireFormat::ReadFixed(input, &number_of_rows))
        throw std::runtime_error("Failed to read number of rows in index column.");

    if (number_of_rows != rows)
        throw std::runtime_error("LowCardinality column must be read in full.");

    new_index_column->Load(input, number_of_rows);

    ColumnLowCardinality::UniqueItems new_unique_items_map;
    for (size_t i = 0; i < new_dictionary_column->Size(); ++i) {
        const auto key = ColumnLowCardinality::computeHashKey(new_dictionary_column->GetItem(i));
        new_unique_items_map.emplace(key, i);
    }

    // suffix
    // NOP

    return std::make_tuple(new_dictionary_column, new_index, new_unique_items_map);
}

}

bool ColumnLowCardinality::Load(CodedInputStream* input, size_t rows) {

    try {
        auto [new_dictionary, new_index, new_unique_items_map] = ::Load(dictionary->Slice(0, 0), input, rows);

        dictionary.swap(new_dictionary);
        index.swap(new_index);
        unique_items_map.swap(new_unique_items_map);

        return true;
    } catch (...) {
        return false;
    }
}

void ColumnLowCardinality::Save(CodedOutputStream* output) {
    // BUG(nemkov): ENSURE THAT DICTIONARY HAS A NULL-value as first item.

    // prefix
    const uint64_t version = static_cast<uint64_t>(KeySerializationVersion::SharedDictionariesWithAdditionalKeys);
    WireFormat::WriteFixed(output, version);

    // body
    const uint64_t index_serialization_type = indexTypeFromIndexColumn(index) | IndexFlag::HasAdditionalKeysBit;
    WireFormat::WriteFixed(output, index_serialization_type);

    const uint64_t number_of_keys = dictionary->Size();
    WireFormat::WriteFixed(output, number_of_keys);
    dictionary->Save(output);

    const auto index_column = getColumnFromVariant(index);
    const uint64_t number_of_rows = index_column->Size();
    WireFormat::WriteFixed(output, number_of_rows);
    index_column->Save(output);

    // suffix
    // NOP
}

void ColumnLowCardinality::Clear() {
    getColumnFromVariant(index)->Clear();
    dictionary->Clear();
}

size_t ColumnLowCardinality::Size() const {
    return getColumnFromVariant(index)->Size();
}

ColumnRef ColumnLowCardinality::Slice(size_t begin, size_t len) {
    begin = std::min(begin, Size());
    len = std::min(len, Size() - begin);

    ColumnRef new_dictionary = dictionary->Slice(0, 0);
    auto result = std::make_shared<ColumnLowCardinality>(new_dictionary);

    for (size_t i = begin; i < begin + len; ++i)
        result->AppendFrom(*this, i);

    return result;
}

void ColumnLowCardinality::Swap(Column& other) {
    auto col = dynamic_cast<ColumnLowCardinality*>(&other);
    if (!col || !dictionary->Type()->IsEqual(col->dictionary->Type()))
        return;

    dictionary.swap(col->dictionary);
    index.swap(col->index);
    unique_items_map.swap(col->unique_items_map);
}

ItemView ColumnLowCardinality::GetItem(size_t index) const {
    return dictionary->GetItem(getDictionaryIndex(index));
}

void ColumnLowCardinality::AppendFrom(const Column& col, size_t index) {
    auto c = dynamic_cast<const ColumnLowCardinality*>(&col);
    if (!c || !dictionary->Type()->IsEqual(c->dictionary->Type()))
        return;

    AppendUnsafe(c->GetItem(index));
}

// No checks regarding value type or validity of value is made.
void ColumnLowCardinality::AppendUnsafe(const ItemView & value) {
    const auto key = computeHashKey(value);

    // If the value is unique, then we are going to append it to a dictionary, hence new index is Size().
    auto [iterator, is_new_item] = unique_items_map.try_emplace(key, dictionary->Size());

    try {
        // Order is important, adding to dictionary last, since it is much (MUCH!!!!) harder
        // to remove item from dictionary column than from index column (also, there is currently no API to do that).
        // Hence in catch-block we assume that dictionary wasn't modified on exception
        // and there is nothing to rollback.

        appendIndex(iterator->second);
        if (is_new_item) {
            AppendToDictionary(dictionary, value);
        }
    }
    catch (...) {
        removeLastIndex();
        if (is_new_item)
            unique_items_map.erase(iterator);

        throw;
    }
}

size_t ColumnLowCardinality::GetDictionarySize() const {
    return dictionary->Size();
}

TypeRef ColumnLowCardinality::GetNestedType() const {
    return dictionary->Type();
}

}