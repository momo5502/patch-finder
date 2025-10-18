#pragma once

#include <map>
#include <string>
#include <vector>

#include "win_pefile.hpp"
#include "buffer_accessor.hpp"

namespace momo
{
    using section_data = std::vector<uint8_t>;
    using section_map = std::map<uint64_t, section_data>;

    namespace detail
    {
        template <typename SpanElement>
        utils::safe_object_accessor<PEDosHeader_t, SpanElement> get_dos_header(const utils::safe_buffer_accessor<SpanElement>& buffer)
        {
            return buffer.template as<PEDosHeader_t>(0);
        }

        template <typename AddrType, typename SpanElement>
        utils::safe_object_accessor<PENTHeaders_t<AddrType>, SpanElement> get_nt_headers(
            const utils::safe_buffer_accessor<SpanElement>& buffer)
        {
            const auto dos_header = get_dos_header(buffer).get();
            const auto nt_headers_offset = dos_header.e_lfanew;

            return buffer.template as<PENTHeaders_t<AddrType>>(nt_headers_offset);
        }

        // TODO: Fix
        template <typename AddrType>
        uint64_t get_first_section_offset(const PENTHeaders_t<AddrType>& nt_headers, const uint64_t nt_headers_offset)
        {
            const auto* nt_headers_addr = reinterpret_cast<const uint8_t*>(&nt_headers);
            const size_t optional_header_offset =
                reinterpret_cast<uintptr_t>(&(nt_headers.OptionalHeader)) - reinterpret_cast<uintptr_t>(&nt_headers);
            const size_t optional_header_size = nt_headers.FileHeader.SizeOfOptionalHeader;
            const auto* first_section_addr = nt_headers_addr + optional_header_offset + optional_header_size;

            const auto first_section_absolute = reinterpret_cast<uint64_t>(first_section_addr);
            const auto absolute_base = reinterpret_cast<uint64_t>(&nt_headers);
            return nt_headers_offset + (first_section_absolute - absolute_base);
        }

        template <typename AddrType, typename SpanElement, typename Accessor>
        void access_sections(const utils::safe_buffer_accessor<SpanElement> buffer, const PENTHeaders_t<AddrType>& nt_headers,
                             const uint64_t nt_headers_offset, const Accessor& accessor)
        {
            const auto first_section_offset = get_first_section_offset(nt_headers, nt_headers_offset);
            const auto sections = buffer.template as<IMAGE_SECTION_HEADER>(static_cast<size_t>(first_section_offset));

            for (size_t i = 0; i < nt_headers.FileHeader.NumberOfSections; ++i)
            {
                const auto section = sections.get(i);

                if (!accessor(section))
                {
                    break;
                }
            }
        }

        template <typename AddrType, typename SpanElement>
        std::optional<size_t> rva_to_file_offset(const utils::safe_buffer_accessor<SpanElement> buffer,
                                                 const PENTHeaders_t<AddrType>& nt_headers, const uint64_t nt_headers_offset,
                                                 const uint32_t rva)
        {
            std::optional<size_t> result{};

            access_sections(buffer, nt_headers, nt_headers_offset, [&](const IMAGE_SECTION_HEADER& section) {
                const auto size_of_data = std::min(section.SizeOfRawData, section.Misc.VirtualSize);
                if (section.VirtualAddress <= rva && (section.VirtualAddress + size_of_data) > rva)
                {
                    result = section.PointerToRawData + rva - section.VirtualAddress;
                    return false;
                }

                return true;
            });

            return result;
        }

        template <typename AddrType, typename SpanElement>
        section_map parse_sections(const utils::safe_buffer_accessor<SpanElement> buffer, const PENTHeaders_t<AddrType>& nt_headers,
                                   const uint64_t nt_headers_offset, const uint64_t base_address)
        {
            section_map result{};

            access_sections(buffer, nt_headers, nt_headers_offset, [&](const IMAGE_SECTION_HEADER& section) {
                if (section.SizeOfRawData <= 0 || !(section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
                {
                    return true;
                }

                const auto target_ptr = base_address + section.VirtualAddress;

                const auto size_of_data = std::min(section.SizeOfRawData, section.Misc.VirtualSize);
                const auto* byte_ptr = buffer.get_pointer_for_range(section.PointerToRawData, size_of_data);
                const auto* source_ptr = reinterpret_cast<const uint8_t*>(byte_ptr);

                section_data data{};
                data.assign(source_ptr, source_ptr + size_of_data);

                result[target_ptr] = std::move(data);
                return true;
            });

            return result;
        }

        inline section_map::iterator find_section(section_map& sections, const uint64_t address)
        {
            auto iter = sections.upper_bound(address);
            if (iter == sections.begin())
            {
                return sections.end();
            }

            std::advance(iter, -1);

            const auto offset = address -iter->first;
            if (offset < sections.size())
            {
                return iter;
            }

            return sections.end();
            
        }

        template <typename T>
            requires(std::is_integral_v<T>)
        bool apply_relocation(section_map& sections, const uint64_t address, const uint64_t delta)
        {
            auto section = find_section(sections, address);
            if (section == sections.end())
            {
                return false;
            }

            utils::safe_buffer_accessor<uint8_t> buffer{section->second};

            const auto offset = address - section->first;
            const auto obj = buffer.template as<T>(static_cast<size_t>(offset));
            const auto value = obj.get();
            const auto new_value = value + static_cast<T>(delta);
            obj.set(new_value);

            return true;
        }

        template <typename AddrType, typename SpanElement>
        void apply_relocations(const utils::safe_buffer_accessor<SpanElement> buffer, const PENTHeaders_t<AddrType>& nt_headers,
                               const uint64_t nt_headers_offset, section_map& sections, const int64_t delta, const uint64_t base_address)
        {
            if (delta == 0)
            {
                return;
            }

            const auto* directory = &nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (directory->Size == 0)
            {
                return;
            }

            auto relocation_offset = directory->VirtualAddress;
            const auto relocation_end = relocation_offset + directory->Size;

            auto relocation_file_offset = rva_to_file_offset(buffer, nt_headers, nt_headers_offset, relocation_offset);
            if (!relocation_file_offset.has_value())
            {
                return;
            }

            while (relocation_offset < relocation_end)
            {
                const auto relocation = buffer.template as<IMAGE_BASE_RELOCATION>(*relocation_file_offset).get();

                if (relocation.VirtualAddress <= 0 || relocation.SizeOfBlock <= sizeof(IMAGE_BASE_RELOCATION))
                {
                    break;
                }

                const auto data_size = relocation.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
                const auto entry_count = data_size / sizeof(uint16_t);

                const auto entries = buffer.template as<uint16_t>(*relocation_file_offset + sizeof(IMAGE_BASE_RELOCATION));

                relocation_offset += relocation.SizeOfBlock;
                *relocation_file_offset += relocation.SizeOfBlock;

                for (size_t i = 0; i < entry_count; ++i)
                {
                    const auto entry = entries.get(i);

                    const int type = entry >> 12;
                    const auto offset = static_cast<uint16_t>(entry & 0xfff);
                    const auto address = base_address + relocation.VirtualAddress + offset;

                    switch (type)
                    {
                    case IMAGE_REL_BASED_ABSOLUTE:
                        break;

                    case IMAGE_REL_BASED_HIGHLOW:
                        apply_relocation<uint32_t>(sections, address, delta);
                        break;

                    case IMAGE_REL_BASED_DIR64:
                        apply_relocation<uint64_t>(sections, address, delta);
                        break;

                    default:
                        throw std::runtime_error("Unknown relocation type: " + std::to_string(type));
                    }
                }
            }
        }

        template <typename AddrType, typename SpanElement>
        section_map parse_pe_variant(const utils::safe_buffer_accessor<SpanElement>& buffer, const uint64_t base_address)
        {
            const auto dos_header = get_dos_header(buffer).get();
            const auto nt_headers_offset = dos_header.e_lfanew;
            const auto nt_headers = get_nt_headers<AddrType>(buffer).get();
            const int64_t aslr_slide = base_address - nt_headers.OptionalHeader.ImageBase;

            auto sections = parse_sections(buffer, nt_headers, nt_headers_offset, base_address);
            apply_relocations(buffer, nt_headers, nt_headers_offset, sections, aslr_slide, base_address);

            return sections;
        }
    }

    template <typename SpanElement>
    section_map parse_pe_file(const utils::safe_buffer_accessor<SpanElement>& buffer, const uint64_t base_address)
    {
        const auto nt_headers = detail::get_nt_headers<uint64_t>(buffer);
        const auto machine_type = nt_headers.get().FileHeader.Machine;

        switch (machine_type)
        {
        case PEMachineType::I386:
            return detail::parse_pe_variant<uint32_t>(buffer, base_address);
        case PEMachineType::AMD64:
            return detail::parse_pe_variant<uint64_t>(buffer, base_address);
        default:
            return {};
        }
    }
}
