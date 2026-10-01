package gitobj

import "sort"

func sortEntries(entries []TreeEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		return compareEntries(entries[i], entries[j]) < 0
	})
}

// sortObjects sorts objects by ascending ID.
func sortObjects(objs []Object) {
	ids := make([]ID, len(objs))
	for i, o := range objs {
		ids[i] = o.ID()
	}
	sort.Sort(&objSorter{objs, ids})
}

type objSorter struct {
	objs []Object
	ids  []ID
}

func (s *objSorter) Len() int           { return len(s.objs) }
func (s *objSorter) Less(i, j int) bool { return compareIDs(s.ids[i], s.ids[j]) < 0 }
func (s *objSorter) Swap(i, j int) {
	s.objs[i], s.objs[j] = s.objs[j], s.objs[i]
	s.ids[i], s.ids[j] = s.ids[j], s.ids[i]
}
